package errors

import (
	stderrors "errors"
)

type Cause interface {
	Cause() error
}

type DetailedError interface {
	Details() string
	Code() string
}

type Error struct {
	Message string
	code    string
	details string
	cause   error
}

func New(message string) error {
	return &Error{
		Message: message,
		code:    "error",
		details: "",
	}
}

func NewDetails(message, code, details string) error {
	return &Error{
		Message: message,
		code:    code,
		details: details,
	}
}

func WithCause(err error, cause error) error {
	if err == nil {
		return nil
	}

	if e, ok := err.(*Error); ok {
		e.cause = cause
		return e
	}

	return &Error{
		Message: err.Error(),
		code:    "error",
		details: "",
		cause:   cause,
	}
}

func WithCode(err error, code string) error {
	if err == nil {
		return nil
	}

	if e, ok := err.(*Error); ok {
		e.code = code
		return e
	}

	return &Error{
		Message: err.Error(),
		code:    code,
		details: "",
	}
}

func WithDetails(err error, details string) error {
	if err == nil {
		return nil
	}

	if e, ok := err.(*Error); ok {
		e.details = details
		return e
	}
	return &Error{
		Message: err.Error(),
		code:    "error",
		details: details,
		cause:   err,
	}
}

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) Cause() error {
	if e.cause != nil {
		return e.cause
	}
	return stderrors.New(e.Message)
}

func (e *Error) Details() string {
	if e.details != "" {
		return e.details
	}
	if e.cause != nil {
		if cause, ok := e.cause.(Cause); ok {
			return cause.Cause().Error()
		}
		return e.cause.Error()
	}
	return ""
}

func (e *Error) Code() string {
	if e.code != "" {
		return e.code
	}
	if e.cause != nil {
		if cause, ok := e.cause.(DetailedError); ok {
			return cause.Code()
		}
	}
	return "error"
}

// Is reports whether any error in err's chain matches target.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error is considered to match a target if it is equal to that target or if
// it implements a method Is(error) bool such that Is(target) returns true.
func Is(err, target error) bool { return stderrors.Is(err, target) }

// As finds the first error in err's chain that matches target, and if so, sets
// target to that error value and returns true.
//
// The chain consists of err itself followed by the sequence of errors obtained by
// repeatedly calling Unwrap.
//
// An error matches target if the error's concrete value is assignable to the value
// pointed to by target, or if the error has a method As(interface{}) bool such that
// As(target) returns true. In the latter case, the As method is responsible for
// setting target.
//
// As will panic if target is not a non-nil pointer to either a type that implements
// error, or to any interface type. As returns false if err is nil.
func As(err error, target interface{}) bool { return stderrors.As(err, target) }

// Unwrap returns the result of calling the Unwrap method on err, if err's
// type contains an Unwrap method returning error.
// Otherwise, Unwrap returns nil.
func Unwrap(err error) error {
	return stderrors.Unwrap(err)
}
