// Package router holds the JSON response and request helpers.
package router

import (
	"encoding/json"
	"errors"
	"mime"
	nethttp "net/http"
	"strconv"
	"time"

	"github.com/boson-chat/pushrelay/internal/apperr"
	"github.com/boson-chat/pushrelay/internal/logger"
)

// MaxBody caps JSON request bodies.
const MaxBody = 64 << 10

// ErrorBody is every error response: {"error": code, "message": text, "code": code}.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// WriteJSON writes v with status (no body for nil / 204).
func WriteJSON(w nethttp.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil && status != nethttp.StatusNoContent {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// WriteError renders apperr errors as-is and anything else as a logged 500.
func WriteError(w nethttp.ResponseWriter, r *nethttp.Request, err error) {
	if e, ok := apperr.As(err); ok {
		if e.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int((e.RetryAfter+time.Second-1)/time.Second)))
		}
		WriteJSON(w, e.Status, ErrorBody{Error: e.Code, Message: e.Message, Code: e.Code})
		return
	}
	logger.FromCtx(r.Context()).Error().Err(err).Str("path", r.URL.Path).Msg("internal error")
	WriteJSON(w, nethttp.StatusInternalServerError, ErrorBody{Error: "internal_error", Message: "internal error", Code: "internal_error"})
}

var errUnsupportedMedia = apperr.New(nethttp.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")

// Decode reads a JSON body (Content-Type application/json required, which
// also keeps plain cross-site HTML forms out).
func Decode(w nethttp.ResponseWriter, r *nethttp.Request, dst any) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return errUnsupportedMedia
	}
	r.Body = nethttp.MaxBytesReader(w, r.Body, MaxBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *nethttp.MaxBytesError
		if errors.As(err, &mbe) {
			return apperr.New(nethttp.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		}
		return apperr.Invalid("malformed JSON body")
	}
	return nil
}

// DecodeOptional is Decode for bodies that may be empty.
func DecodeOptional(w nethttp.ResponseWriter, r *nethttp.Request, dst any) error {
	if r.ContentLength == 0 {
		return nil
	}
	return Decode(w, r, dst)
}
