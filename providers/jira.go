// Jira Cloud provider — implements ContextValidator against the Jira Cloud
// REST API v3. It verifies that (a) the issue exists, (b) its status is
// "In Progress", and (c) the requesting user matches the assignee.
package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// JiraClient is the concrete ContextValidator backed by Jira Cloud.
type JiraClient struct {
	BaseURL    string
	Username   string
	APIToken   string
	HTTPClient *http.Client
}

// jiraIssue models the slice of the Jira issue payload we need.
type jiraIssue struct {
	Fields struct {
		Status struct {
			Name string `json:"name"`
		} `json:"status"`
		Assignee struct {
			AccountID   string `json:"accountId"`
			EmailAddress string `json:"emailAddress"`
			DisplayName string `json:"displayName"`
		} `json:"assignee"`
	} `json:"fields"`
}

// Validate implements ContextValidator.
func (j *JiraClient) Validate(ctx context.Context, user, ref string) (bool, string, error) {
	if strings.TrimSpace(ref) == "" {
		return false, "missing issue key", nil
	}
	url := strings.TrimRight(j.BaseURL, "/") + "/rest/api/3/issue/" + ref + "?fields=status,assignee"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, "", err
	}
	// Jira Cloud uses HTTP Basic auth with email + API token.
	auth := j.Username + ":" + j.APIToken
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	req.Header.Set("Accept", "application/json")

	client := j.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("jira: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, "issue " + ref + " not found", nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, "", fmt.Errorf("jira: unexpected status %d: %s", resp.StatusCode, body)
	}

	var issue jiraIssue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return false, "", fmt.Errorf("jira: decode: %w", err)
	}

	if !strings.EqualFold(issue.Fields.Status.Name, "In Progress") {
		return false, fmt.Sprintf("issue status is %q, must be In Progress", issue.Fields.Status.Name), nil
	}
	a := issue.Fields.Assignee
	if a.AccountID == "" && a.EmailAddress == "" {
		return false, "issue has no assignee", nil
	}
	if a.AccountID == user || strings.EqualFold(a.EmailAddress, user) || strings.EqualFold(a.DisplayName, user) {
		return true, "", nil
	}
	return false, "user " + user + " is not the assignee of issue " + ref, nil
}

// Name returns the provider identifier.
func (j *JiraClient) Name() string { return "jira" }