// Package coverage implements the provider's client for the coordinator's
// retention-authority coverage endpoint plus the batch-refresh orchestration
// that updates the local coverage cache.
//
// Spec: docs/retention_authority_design.md §4.1, §6.2, §6.6.
package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNonRetryable indicates a 4xx response from the coord. Retrying would
// produce the same result; callers should log and move on.
var ErrNonRetryable = errors.New("coverage query failed with non-retryable status")

// Request is the body sent to POST /v1/provider/roots/status. Matches the
// coord-side api.ProviderRootsStatusRequest exactly; redefined here to
// avoid a reverse import on the coord module.
type Request struct {
	Roots []string `json:"roots"`
}

// RootStatus matches the per-root value in the coord response. Kept
// aligned with api.RootStatus byte-for-byte.
type RootStatus struct {
	Status string `json:"status"`
	Until  string `json:"until,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Response is the decoded coord response: a map keyed by merkle root hex.
type Response map[string]RootStatus

// Client is an HTTP client for the coord's coverage endpoint. Safe for
// concurrent use.
type Client struct {
	// CoordURL is the base URL, e.g. "https://coordinator.obsideo.io".
	// No trailing slash; the client appends the endpoint path.
	CoordURL string

	// APIKey is the provider API key sent as `Authorization: Bearer`.
	APIKey string

	// HTTP is the underlying transport. Nil uses http.DefaultClient, which
	// is fine for tests; production callers set a timeout-bearing client.
	HTTP *http.Client

	// MaxRetries is the number of retry attempts for transient failures
	// (network errors, 5xx). Zero means a single attempt with no retry.
	// Design default: 3.
	MaxRetries int

	// BackoffFloor is the minimum delay between retries (exponential
	// starts at this value and doubles each attempt). Design §6.6:
	// a floor prevents hammering a recovering coord.
	BackoffFloor time.Duration

	// BackoffCeiling caps the per-retry delay. Also the retention against
	// unbounded growth of the backoff sequence.
	BackoffCeiling time.Duration
}

// NewClient returns a Client with sensible Phase 1 defaults for retry
// behavior. Operators override fields directly on the returned value.
func NewClient(coordURL, apiKey string, httpClient *http.Client) *Client {
	return &Client{
		CoordURL:       strings.TrimRight(coordURL, "/"),
		APIKey:         apiKey,
		HTTP:           httpClient,
		MaxRetries:     3,
		BackoffFloor:   1 * time.Second,
		BackoffCeiling: 30 * time.Second,
	}
}

// QueryRoots sends one coverage-status query and returns the decoded
// response. Retries 5xx and network errors up to MaxRetries; returns
// ErrNonRetryable on 4xx (wrapping the response body for the caller's
// log). A returned error means the caller got no usable answer and MUST
// NOT treat any root as uncovered/orphaned from this call; that is the
// retain-everything rule from design §6.6.
func (c *Client) QueryRoots(ctx context.Context, roots []string) (Response, error) {
	if len(roots) == 0 {
		return Response{}, nil
	}
	body, err := json.Marshal(Request{Roots: roots})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.backoffDuration(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := c.doOnce(ctx, body)
		if err == nil {
			return resp, nil
		}
		// 4xx → no retry; caller should log and move on.
		if errors.Is(err, ErrNonRetryable) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("coverage query: all retries exhausted: %w", lastErr)
}

func (c *Client) doOnce(ctx context.Context, body []byte) (Response, error) {
	url := c.CoordURL + "/v1/provider/roots/status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	// For 2xx we need the body; for 4xx/5xx the body is the error detail.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// 4xx: non-retryable. Include body text in the error for ops.
		return nil, fmt.Errorf("%w: coord %d: %s", ErrNonRetryable, resp.StatusCode, truncate(respBody, 256))
	}
	if resp.StatusCode >= 500 {
		// 5xx: retryable. Not ErrNonRetryable; caller loop will backoff.
		return nil, fmt.Errorf("coord %d: %s", resp.StatusCode, truncate(respBody, 256))
	}
	if readErr != nil {
		return nil, fmt.Errorf("read body: %w", readErr)
	}
	var decoded Response
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return decoded, nil
}

// backoffDuration computes the delay before retry `attempt` (1-indexed).
// Exponential starting at BackoffFloor, capped at BackoffCeiling.
func (c *Client) backoffDuration(attempt int) time.Duration {
	d := c.BackoffFloor
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > c.BackoffCeiling {
			return c.BackoffCeiling
		}
	}
	if d > c.BackoffCeiling {
		return c.BackoffCeiling
	}
	return d
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
