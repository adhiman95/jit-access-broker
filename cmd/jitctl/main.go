// jitctl is a lightweight CLI for the JIT Access Broker.
//
// Usage:
//
//	jitctl --cmd request  --user alice@example.com --resource prod-db --type pagerduty --ref Q3ABC123
//	jitctl --cmd extend   --id tok_abc123 --user alice@example.com --type pagerduty --ref Q3ABC123
//	jitctl --cmd list
//	jitctl --cmd revoke   --id tok_abc123
//	jitctl --cmd health
//
// All flags are optional except the command-specific ones noted above.
// The broker URL defaults to http://localhost:8080 and can be overridden
// with --broker.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	cmd := flag.String("cmd", "", "command: request|extend|list|revoke|health")
	broker := flag.String("broker", "http://localhost:8080", "broker base URL")
	user := flag.String("user", "", "user identity (email)")
	resource := flag.String("resource", "", "target resource")
	jType := flag.String("type", "", "justification type: pagerduty|jira")
	ref := flag.String("ref", "", "justification ref (incident id / issue key)")
	id := flag.String("id", "", "token id (for extend/revoke)")
	flag.Parse()

	switch *cmd {
	case "request":
		if *user == "" || *resource == "" || *jType == "" || *ref == "" {
			fmt.Fprintln(os.Stderr, "request requires --user, --resource, --type, --ref")
			os.Exit(1)
		}
		body := map[string]string{
			"user_identity":      *user,
			"resource":           *resource,
			"justification_type": *jType,
			"justification_ref":  *ref,
		}
		resp := postJSON(*broker+"/api/v1/access/request", body)
		fmt.Println(resp)

	case "extend":
		if *id == "" || *user == "" || *jType == "" || *ref == "" {
			fmt.Fprintln(os.Stderr, "extend requires --id, --user, --type, --ref")
			os.Exit(1)
		}
		body := map[string]string{
			"token_id":           *id,
			"user_identity":      *user,
			"justification_type": *jType,
			"justification_ref":  *ref,
		}
		resp := postJSON(*broker+"/api/v1/access/extend", body)
		fmt.Println(resp)

	case "list":
		resp := getJSON(*broker + "/api/v1/access/tokens")
		fmt.Println(resp)

	case "revoke":
		if *id == "" {
			fmt.Fprintln(os.Stderr, "revoke requires --id")
			os.Exit(1)
		}
		resp := postJSON(*broker+"/api/v1/access/revoke/"+*id, nil)
		fmt.Println(resp)

	case "health":
		resp := getJSON(*broker + "/healthz")
		fmt.Println(resp)

	default:
		fmt.Fprintln(os.Stderr, "unknown --cmd. Use: request|extend|list|revoke|health")
		os.Exit(1)
	}
}

func postJSON(url string, body any) string {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(http.MethodPost, url, r)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(b))
}

func getJSON(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(b))
}