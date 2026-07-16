// Command aegis-qa executes and verifies the independently governed AegisLLM
// black-box baseline. User-visible output is restricted to classification codes.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/artifact"
	"github.com/yknothing/AegisLLM-QA/internal/evidence"
	"github.com/yknothing/AegisLLM-QA/internal/suite"
)

var qaCommit = "unbuilt"

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return emit(stderr, 2, "qa_usage_error")
	}
	switch args[0] {
	case "run":
		return executeRun(args[1:], stdout, stderr)
	case "verify":
		return executeVerify(args[1:], stdout, stderr)
	default:
		return emit(stderr, 2, "qa_usage_error")
	}
}

type runOptions struct {
	sut            string
	sourceSHA      string
	headSHA        string
	baseSHA        string
	qaSHA          string
	artifactSHA256 string
	workflowRunID  string
	evidencePath   string
	timeout        time.Duration
}

func executeRun(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return emit(stderr, 2, "qa_usage_error")
	}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options runOptions
	flags.StringVar(&options.sut, "sut", "", "absolute SUT path")
	flags.StringVar(&options.sourceSHA, "source-sha", "", "tested source commit")
	flags.StringVar(&options.headSHA, "head-sha", "", "candidate head commit")
	flags.StringVar(&options.baseSHA, "base-sha", "", "candidate base commit")
	flags.StringVar(&options.qaSHA, "qa-sha", "", "QA baseline commit")
	flags.StringVar(&options.artifactSHA256, "artifact-sha256", "", "external artifact digest")
	flags.StringVar(&options.workflowRunID, "workflow-run-id", "", "workflow run identity")
	flags.StringVar(&options.evidencePath, "evidence", "", "new evidence path")
	flags.DurationVar(&options.timeout, "timeout", 0, "suite deadline")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return emit(stderr, 2, "qa_usage_error")
	}
	binding := evidence.Binding{
		SourceSHA: options.sourceSHA, HeadSHA: options.headSHA, BaseSHA: options.baseSHA,
		QASHA: options.qaSHA, ArtifactSHA256: options.artifactSHA256, WorkflowRunID: options.workflowRunID,
	}
	if err := validateRunOptions(options, binding); err != nil {
		return emit(stderr, 2, "qa_binding_invalid")
	}
	if qaCommit != options.qaSHA {
		return emit(stderr, 2, "qa_runner_identity_invalid")
	}
	if err := validateSUTPath(options.sut); err != nil {
		return emit(stderr, 2, "qa_binding_invalid")
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	identity, err := artifact.Inspect(ctx, options.sut, artifact.Expected{
		SourceSHA: options.sourceSHA, ArtifactSHA256: options.artifactSHA256,
	})
	if err != nil {
		return emit(stderr, 1, "qa_artifact_invalid")
	}
	runContext := &suite.Context{
		Binary: options.sut, Binding: binding, Identity: identity, StartedAt: time.Now().UTC(),
	}
	report := suite.Run(ctx, runContext, suite.Baseline())
	forbiddenCanaries := runContext.ForbiddenCanaries()
	defer func() {
		for index := range forbiddenCanaries {
			forbiddenCanaries[index] = ""
		}
		runContext.ClearCanaries()
	}()
	if err := artifact.VerifyUnchanged(options.sut, identity); err != nil {
		forceCaseFailure(&report, "artifact_identity", "artifact_changed")
	}
	required := suite.RequiredCases()
	if report.Status != evidence.StatusPass {
		// Persist structurally valid sanitized failure evidence. Verification still
		// supplies the governed required set and therefore rejects this report.
		required = nil
	}
	if err := evidence.WriteAtomicExclusive(options.evidencePath, report, required, forbiddenCanaries); err != nil {
		return emit(stderr, 1, "qa_evidence_write_failed")
	}
	if report.Status != evidence.StatusPass {
		return emit(stderr, 1, "qa_run_fail")
	}
	return emit(stdout, 0, "qa_run_pass")
}

type verifyOptions struct {
	sut                  string
	evidencePath         string
	expectSourceSHA      string
	expectHeadSHA        string
	expectBaseSHA        string
	expectQASHA          string
	expectArtifactSHA256 string
	expectWorkflowRunID  string
}

func executeVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return emit(stderr, 2, "qa_usage_error")
	}
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options verifyOptions
	flags.StringVar(&options.sut, "sut", "", "absolute SUT path")
	flags.StringVar(&options.evidencePath, "evidence", "", "evidence path")
	flags.StringVar(&options.expectSourceSHA, "expect-source-sha", "", "external source commit")
	flags.StringVar(&options.expectHeadSHA, "expect-head-sha", "", "external head commit")
	flags.StringVar(&options.expectBaseSHA, "expect-base-sha", "", "external base commit")
	flags.StringVar(&options.expectQASHA, "expect-qa-sha", "", "external QA commit")
	flags.StringVar(&options.expectArtifactSHA256, "expect-artifact-sha256", "", "external artifact digest")
	flags.StringVar(&options.expectWorkflowRunID, "expect-workflow-run-id", "", "external workflow run identity")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return emit(stderr, 2, "qa_usage_error")
	}
	binding := evidence.Binding{
		SourceSHA: options.expectSourceSHA, HeadSHA: options.expectHeadSHA, BaseSHA: options.expectBaseSHA,
		QASHA: options.expectQASHA, ArtifactSHA256: options.expectArtifactSHA256, WorkflowRunID: options.expectWorkflowRunID,
	}
	if err := validateVerifyOptions(options, binding); err != nil {
		return emit(stderr, 2, "qa_binding_invalid")
	}
	if qaCommit != options.expectQASHA {
		return emit(stderr, 2, "qa_runner_identity_invalid")
	}
	if err := validateSUTPath(options.sut); err != nil {
		return emit(stderr, 2, "qa_binding_invalid")
	}
	if _, err := evidence.ReadAndVerify(options.evidencePath, binding, suite.RequiredCases(), nil); err != nil {
		return emit(stderr, 1, "qa_evidence_invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := artifact.Inspect(ctx, options.sut, artifact.Expected{
		SourceSHA: options.expectSourceSHA, ArtifactSHA256: options.expectArtifactSHA256,
	})
	if err != nil {
		return emit(stderr, 1, "qa_artifact_invalid")
	}
	if err := artifact.VerifyUnchanged(options.sut, identity); err != nil {
		return emit(stderr, 1, "qa_artifact_changed")
	}
	return emit(stdout, 0, "qa_verify_pass")
}

func validateRunOptions(options runOptions, binding evidence.Binding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(options.headSHA) == "" || strings.TrimSpace(options.workflowRunID) == "" {
		return fmt.Errorf("missing required provenance")
	}
	if options.timeout <= 0 || options.timeout > 10*time.Minute {
		return fmt.Errorf("invalid timeout")
	}
	if !absoluteCleanPath(options.sut) || !absoluteCleanPath(options.evidencePath) {
		return fmt.Errorf("invalid path")
	}
	if _, err := os.Lstat(options.evidencePath); err == nil || !os.IsNotExist(err) {
		return fmt.Errorf("evidence path is not new")
	}
	return nil
}

func validateVerifyOptions(options verifyOptions, binding evidence.Binding) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(options.expectHeadSHA) == "" || strings.TrimSpace(options.expectWorkflowRunID) == "" {
		return fmt.Errorf("missing required provenance")
	}
	if !absoluteCleanPath(options.sut) || !absoluteCleanPath(options.evidencePath) {
		return fmt.Errorf("invalid path")
	}
	return nil
}

func absoluteCleanPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validateSUTPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("SUT unavailable")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("SUT is not executable")
	}
	return nil
}

func forceCaseFailure(report *evidence.Report, name, detail string) {
	if report == nil {
		return
	}
	report.Status = evidence.StatusFail
	for index := range report.Cases {
		if report.Cases[index].Name == name {
			report.Cases[index].Status = evidence.StatusFail
			report.Cases[index].Detail = detail
			return
		}
	}
}

func emit(writer io.Writer, code int, classification string) int {
	_, _ = fmt.Fprintln(writer, classification)
	return code
}
