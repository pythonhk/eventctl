//go:build windows

package bundle

import "os"

// os.Rename uses MoveFile on Windows and fails when destination already exists.
func renameNoReplace(source, destination string) error {
	return os.Rename(source, destination)
}
