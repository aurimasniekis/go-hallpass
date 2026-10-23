// Package apperr defines domain errors with stable codes shared by services, the REST API (RFC 9457 problem codes)
// and the SSH front end.
package apperr

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable error code.
type Code string

// Codes.
const (
	CodeInvalid       Code = "validation_failed"
	CodeNotFound      Code = "not_found"
	CodeAlreadyExists Code = "already_exists"
	CodeConflict      Code = "conflict"
	CodeForbidden     Code = "forbidden"
	CodePrecondition  Code = "precondition_failed"
	CodeUnavailable   Code = "unavailable"
	CodeRateLimited   Code = "rate_limited"
	CodeReauth        Code = "reauth_required"
	CodeMFARequired   Code = "mfa_required"
	CodeUnauthorized  Code = "unauthorized"
)

// FieldError describes one invalid input field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error is a domain error.
type Error struct {
	Code    Code
	Message string
	Fields  []FieldError
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches errors by code, so errors.Is(err, apperr.NotFound("")) works.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Code == e.Code && t.Message == ""
}

// New builds an error with a formatted message.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap attaches a cause.
func Wrap(code Code, err error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Err: err}
}

// Sentinels for errors.Is checks by code.
var (
	ErrInvalid       = &Error{Code: CodeInvalid}
	ErrNotFound      = &Error{Code: CodeNotFound}
	ErrAlreadyExists = &Error{Code: CodeAlreadyExists}
	ErrConflict      = &Error{Code: CodeConflict}
	ErrForbidden     = &Error{Code: CodeForbidden}
	ErrPrecondition  = &Error{Code: CodePrecondition}
	ErrUnavailable   = &Error{Code: CodeUnavailable}
	ErrRateLimited   = &Error{Code: CodeRateLimited}
)

// CodeOf returns the code of err, or "" when err is not an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Validation accumulates field errors.
type Validation struct{ fields []FieldError }

// Add records a field error.
func (v *Validation) Add(field, format string, args ...any) {
	v.fields = append(v.fields, FieldError{Field: field, Message: fmt.Sprintf(format, args...)})
}

// Err returns nil or a validation error listing every field problem.
func (v *Validation) Err() error {
	if len(v.fields) == 0 {
		return nil
	}
	msg := v.fields[0].Field + ": " + v.fields[0].Message
	if len(v.fields) > 1 {
		msg += fmt.Sprintf(" (and %d more)", len(v.fields)-1)
	}
	return &Error{Code: CodeInvalid, Message: msg, Fields: v.fields}
}
