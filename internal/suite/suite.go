// Package suite defines and executes the independent binary-only acceptance
// baseline. It records only stable classification codes, never raw SUT output.
package suite

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/artifact"
	"github.com/yknothing/AegisLLM-QA/internal/evidence"
	"github.com/yknothing/AegisLLM-QA/internal/harness"
)

const (
	DetailPassed         = "passed"
	DetailCaseFailed     = "case_failed"
	DetailDuplicateCase  = "duplicate_case"
	DetailNotRun         = "not_run"
	DetailPanic          = "panic"
	DetailOutputOverflow = "output_overflow"
)

var requiredCases = []string{
	"artifact_identity",
	"network_namespace_isolation",
	"operator_lifecycle",
	"http_unauthenticated_no_egress",
	"http_authenticated_provider_success",
	"http_revoked_no_egress",
	"http_route_and_header_contract",
	"unsupported_capabilities_fail_closed",
	"secret_canary_confinement",
	"process_lifecycle",
}

// Context binds a suite run to independently inspected inputs.
type Context struct {
	Binary    string
	Binding   evidence.Binding
	Identity  artifact.Identity
	StartedAt time.Time

	canaryMu sync.Mutex
	canaries [][]byte
}

// ForbiddenCanaries returns temporary defensive string copies for the
// evidence boundary. Callers must discard the returned slice immediately
// after validation and call ClearCanaries on the run context.
func (c *Context) ForbiddenCanaries() []string {
	if c == nil {
		return nil
	}
	c.canaryMu.Lock()
	defer c.canaryMu.Unlock()
	values := make([]string, len(c.canaries))
	for index, value := range c.canaries {
		values[index] = string(append([]byte(nil), value...))
	}
	return values
}

// ClearCanaries zeroes and releases the suite's in-memory evidence denylist.
func (c *Context) ClearCanaries() {
	if c == nil {
		return
	}
	c.canaryMu.Lock()
	defer c.canaryMu.Unlock()
	for index := range c.canaries {
		clear(c.canaries[index])
		c.canaries[index] = nil
	}
	c.canaries = nil
}

func (c *Context) registerCanary(value []byte) {
	if c == nil || len(value) == 0 {
		return
	}
	c.canaryMu.Lock()
	c.canaries = append(c.canaries, append([]byte(nil), value...))
	c.canaryMu.Unlock()
}

// Case is one required, order-independent black-box contract.
type Case struct {
	Name string
	Run  func(context.Context, *Context) error
}

// RequiredCases returns a defensive copy of the governed baseline IDs.
func RequiredCases() []string {
	return append([]string(nil), requiredCases...)
}

// Run executes each required case exactly once and fails closed for malformed
// registrations, panics, non-runs, output overflow, cancellation, or errors.
func Run(ctx context.Context, runContext *Context, cases []Case) evidence.Report {
	started := time.Now().UTC()
	if runContext != nil && !runContext.StartedAt.IsZero() {
		started = runContext.StartedAt.UTC()
	}
	report := evidence.Report{
		SchemaVersion: evidence.SchemaVersion,
		StartedAt:     started,
		GoVersion:     runtime.Version(),
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Status:        evidence.StatusPass,
		Gaps:          []string{},
	}
	if runContext != nil {
		report.Binding = runContext.Binding
		if runContext.Identity.Toolchain != "" {
			report.GoVersion = runContext.Identity.Toolchain
		}
	}

	registered := make(map[string][]Case, len(cases))
	for _, candidate := range cases {
		registered[candidate.Name] = append(registered[candidate.Name], candidate)
	}
	for _, name := range requiredCases {
		startedCase := time.Now()
		result := evidence.CaseResult{Name: name, Status: evidence.StatusNotRun, Detail: DetailNotRun}
		matches := registered[name]
		switch {
		case len(matches) > 1:
			result.Status = evidence.StatusFail
			result.Detail = DetailDuplicateCase
		case len(matches) == 0 || matches[0].Run == nil || runContext == nil || ctx == nil:
			result.Detail = DetailNotRun
		default:
			caseErr, panicked := invokeCase(ctx, runContext, matches[0].Run)
			switch {
			case panicked:
				result.Status = evidence.StatusFail
				result.Detail = DetailPanic
			case caseErr == nil:
				result.Status = evidence.StatusPass
				result.Detail = DetailPassed
			case errors.Is(caseErr, harness.ErrOutputLimit):
				result.Status = evidence.StatusFail
				result.Detail = DetailOutputOverflow
			default:
				result.Status = evidence.StatusFail
				result.Detail = detailCode(caseErr)
			}
		}
		result.DurationMS = time.Since(startedCase).Milliseconds()
		if result.Status != evidence.StatusPass {
			report.Status = evidence.StatusFail
		}
		report.Cases = append(report.Cases, result)
	}
	report.CompletedAt = time.Now().UTC()
	if report.CompletedAt.Before(report.StartedAt) {
		report.CompletedAt = report.StartedAt
	}
	return report
}

type classifiedError struct{ code string }

func (e classifiedError) Error() string { return e.code }

func failure(code string) error { return classifiedError{code: code} }

func detailCode(err error) string {
	var classified classifiedError
	if errors.As(err, &classified) && validDetailCode(classified.code) {
		return classified.code
	}
	return DetailCaseFailed
}

func validDetailCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, character := range code {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func invokeCase(ctx context.Context, runContext *Context, run func(context.Context, *Context) error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	return run(ctx, runContext), false
}
