//go:build linux
// +build linux

package commands

import (
	"strings"
	"syscall"
	"unsafe"
)

func listXattr(path string) ([]string, error) {
	// First call to get size
	size, err := syscall.Listxattr(path, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	size, err = syscall.Listxattr(path, buf)
	if err != nil {
		return nil, err
	}

	// Names are null-terminated strings concatenated together
	var attrs []string
	for _, name := range strings.Split(string(buf[:size]), "\x00") {
		if name != "" {
			attrs = append(attrs, name)
		}
	}
	return attrs, nil
}

func getXattr(path, name string) ([]byte, error) {
	// First call to get size
	size, err := syscall.Getxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, size)
	size, err = syscall.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:size], nil
}

func setXattr(path, name string, data []byte) error {
	return syscall.Setxattr(path, name, data, 0)
}

func removeXattr(path, name string) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_REMOVEXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(nameBytes)),
		0)
	if errno != 0 {
		return errno
	}
	return nil
}
