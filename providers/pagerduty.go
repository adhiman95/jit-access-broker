// PagerDuty provider — implements ContextValidator against the PagerDuty
// REST API v2. It checks that (a) the incident exists, (b) its status is
// "acknowledged" (the active, in-progress state in PD), and (c) the requesting
// user matches the incident's assigned_to user.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PagerDutyClient is the concrete ContextValidator backed by the PD API.
type PagerDutyClient struct {
	BaseURL    string
	APIToken   string
	HTTPClient *http.Client
}

// pdIncidentEnvelope models the slice of the PD incident payload we need.
type pdIncidentEnvelope struct {
	Incident struct {
		Status      string `json:"status"`
		Assignments []struct {
			Assignee struct {
				ID      string `json:"id"`
				Summary string `json:"summary"`
				HTMLURL string `json:"html_url"`
			} `json:"assignee"`
		} `json:"assignments"`
	} `json:"incident"`
}

// Validate implements ContextValidator.
func (p *PagerDutyClient) Validate(ctx context.Context, user, ref string) (bool, string, error) {
	if strings.TrimSpace(ref) == "" {
		return false, "missing incident id", nil
	}
	url := strings.TrimRight(p.BaseURL, "/") + "/incidents/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Authorization", "Token token="+p.APIToken)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("From", user)

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("pagerduty: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, "incident " + ref + " not found", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, "", fmt.Errorf("pagerduty: unexpected status %d: %s", resp.StatusCode, body)
	}

	var env pdIncidentEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return false, "", fmt.Errorf("pagerduty: decode: %w", err)
	}
	inc := env.Incident

	if inc.Status != "acknowledged" {
		return false, fmt.Sprintf("incident status is %q, must be acknowledged", inc.Status), nil
	}
	if len(inc.Assignments) == 0 {
		return false, "no engineer is assigned to this incident", nil
	}
	for _, a := range inc.Assignments {
		// match on assignee id OR summary (email/name) — case-insensitive on summary
		if a.Assignee.ID == user || strings.EqualFold(a.Assignee.Summary, user) {
			return true, "", nil
		}
	}
	return false, "user " + user + " is not an assignee of incident " + ref, nil
}

// Name returns the provider identifier.
func (p *PagerDutyClient) Name() string { return "pagerduty" }