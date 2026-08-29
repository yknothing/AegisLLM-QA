package suite

import (
	"encoding/json"
	"net/http"
)

const (
	openaiObjectList = "list"
	jwtTPMProbeLimit = 1
)

// acceptAuthenticatedModelsRoute allows the pre-P0 unmounted 404 or a P0
// authenticated OpenAI list that includes the virtual-key model. Any other
// status is fail-closed.
func acceptAuthenticatedModelsRoute(status int, body []byte, permittedModel string) error {
	switch status {
	case http.StatusNotFound:
		return nil
	case http.StatusOK:
		return requireModelsListContains(body, permittedModel)
	default:
		return failure("route_matrix_status_invalid")
	}
}

// requireModelsListContains checks an OpenAI-compatible models list payload.
func requireModelsListContains(body []byte, permittedModel string) error {
	var payload struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return failure("route_matrix_status_invalid")
	}
	if payload.Object != openaiObjectList {
		return failure("route_matrix_status_invalid")
	}
	for _, item := range payload.Data {
		if item.ID == permittedModel {
			return nil
		}
	}
	return failure("route_matrix_status_invalid")
}

// acceptJWTTPMClaim allows legacy reserved 401 (no egress), P0 preflight 429
// (no extra egress), or P0 success 200. Other statuses fail closed.
func acceptJWTTPMClaim(status, hits, baselineHits int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusTooManyRequests:
		if hits != baselineHits {
			return failure("unsupported_claim_allowed")
		}
		return nil
	case http.StatusOK:
		return nil
	default:
		return failure("unsupported_claim_allowed")
	}
}
