package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/pythonhk/eventctl/internal/canonical"
)

const outputVersion = "pythonhk.eventctl/output/v1"

type response struct {
	OutputVersion string       `json:"output_version"`
	OK            bool         `json:"ok"`
	Command       string       `json:"command"`
	Result        any          `json:"result"`
	Error         *errorObject `json:"error"`
}

type errorObject struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type commandError struct {
	Code, Message string
	Exit          int
	Cause         error
}

func (err commandError) Error() string {
	if err.Cause != nil {
		return err.Message + ": " + err.Cause.Error()
	}
	return err.Message
}
func (err commandError) Unwrap() error { return err.Cause }
func usageError(message string) error  { return commandError{Code: "usage", Message: message, Exit: 2} }
func invalidError(message string, cause error) error {
	return commandError{Code: "invalid_input", Message: message, Exit: 2, Cause: cause}
}
func verificationError(message string, cause error) error {
	return commandError{Code: "verification_failed", Message: message, Exit: 3, Cause: cause}
}
func ioError(message string, cause error) error {
	return commandError{Code: "io_error", Message: message, Exit: 4, Cause: cause}
}

func asCommandError(err error) commandError {
	var typed commandError
	if errors.As(err, &typed) {
		return typed
	}
	return commandError{Code: "internal_error", Message: "command failed", Exit: 1, Cause: err}
}

func emitSuccess(output io.Writer, command string, result any) int {
	return emit(output, response{OutputVersion: outputVersion, OK: true, Command: command, Result: result, Error: nil}, 0)
}
func emitFailure(output io.Writer, command string, err commandError) int {
	message := err.Error()
	if message == "" {
		message = "command failed"
	}
	return emit(output, response{OutputVersion: outputVersion, OK: false, Command: command, Result: nil, Error: &errorObject{Code: err.Code, Message: message}}, err.Exit)
}
func emit(output io.Writer, value any, exit int) int {
	raw, err := canonical.Marshal(value)
	if err != nil {
		fmt.Fprintf(output, "{\"ok\":false,\"error\":{\"code\":\"encoding_error\"}}\n")
		return 1
	}
	raw = append(raw, '\n')
	if _, err := output.Write(raw); err != nil {
		return 1
	}
	return exit
}
