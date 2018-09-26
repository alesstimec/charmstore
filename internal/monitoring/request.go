// Copyright 2016 Canonical Ltd.

package monitoring // import "gopkg.in/juju/charmstore.v5/internal/monitoring"

import (
	"net/http"
	"time"
)

// Request represents a monitoring request. To record a request, either
// create a new request with NewRequest or call Reset on an existing
// Request; then call Done when the request has completed.
type Request struct {
	startTime time.Time
	root      string
	kind      string
	request   *http.Request
}

// NewRequest returns a new monitoring request
// for monitoring a request within the given root.
// When the request is done, Done should be called.
func NewRequest(req *http.Request, root string) *Request {
	var r Request
	r.Reset(req, root)
	return &r
}

// Reset resets r to indicate that a new request has started. The
// parameter holds the API root (for example the API version).
func (r *Request) Reset(req *http.Request, root string) {
	r.startTime = time.Now()
	r.request = req
	r.kind = ""
	r.root = root
}

// SetKind sets the kind of the request. This is
// an arbitrary string to classify different kinds of request.
func (r *Request) SetKind(kind string) {
	r.kind = kind
}

// Done records that the request is complete, and records any metrics for the request since the last call to Reset.
func (r *Request) Done() {
	requestDuration.WithLabelValues(r.request.Method, r.root, r.kind).Observe(float64(time.Since(r.startTime)) / float64(time.Second))
}

// Kind returns the kind that has been set. This is useful for testing.
func (r *Request) Kind() string {
	return r.kind
}
