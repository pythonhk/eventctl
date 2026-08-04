package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxSmallFile = 2 << 20

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	reader := io.LimitReader(file, limit+1)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return raw, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("output path is required")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

type stringList []string

func (values *stringList) String() string         { return fmt.Sprint([]string(*values)) }
func (values *stringList) Set(value string) error { *values = append(*values, value); return nil }
