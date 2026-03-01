//go:build darwin
// +build darwin

package commands

import (
	"strings"
	"syscall"
	"unsafe"
)

// macOS xattr syscalls use different numbers than Linux
// listxattr(2), getxattr(2), setxattr(2), removexattr(2)

func listXattr(path string) ([]string, error) {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}

	// First call to get size
	size, _, errno := syscall.Syscall6(
		syscall.SYS_LISTXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		0, 0,
		0, // options
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	size, _, errno = syscall.Syscall6(
		syscall.SYS_LISTXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		0,
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}

	var attrs []string
	for _, name := range strings.Split(string(buf[:size]), "\x00") {
		if name != "" {
			attrs = append(attrs, name)
		}
	}
	return attrs, nil
}

func getXattr(path, name string) ([]byte, error) {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}

	// Get size first
	size, _, errno := syscall.Syscall6(
		syscall.SYS_GETXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(nameBytes)),
		0, 0,
		0, // position
		0, // options
	)
	if errno != 0 {
		return nil, errno
	}
	if size == 0 {
		return []byte{}, nil
	}

	buf := make([]byte, size)
	size, _, errno = syscall.Syscall6(
		syscall.SYS_GETXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(&buf[0])),
		size,
		0, 0,
	)
	if errno != 0 {
		return nil, errno
	}
	return buf[:size], nil
}

func setXattr(path, name string, data []byte) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}

	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(nameBytes)),
		dataPtr,
		uintptr(len(data)),
		0, // position
		0, // options
	)
	if errno != 0 {
		return errno
	}
	return nil
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

	_, _, errno := syscall.Syscall(
		syscall.SYS_REMOVEXATTR,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(nameBytes)),
		0, // options
	)
	if errno != 0 {
		return errno
	}
	return nil
}
