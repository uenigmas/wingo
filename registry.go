package wingo

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// GetRegDirs read contain dirs from windows registry
func GetRegDirs(path string) (ss []string, err error) {
	f, err := exec.Command("cmd", `/C reg query `+path).Output()
	t := strings.Replace(string(f), "\r\n", "\n", -1)
	ts := strings.Split(t, "\n")

	for _, v := range ts {
		if v == "" {
			continue
		}
		ss = append(ss, v)
	}
	return
}

// GetRegASCII read value (base: ascii) from win registry
func GetRegASCII(path, name string) (val []byte, err error) {
	ts := strings.SplitN(path, "\\", 2)
	if len(ts) != 2 {
		err = errors.New("illegal registry path")
		return
	}

	tb, err := GetRegUnicode(ts[0], ts[1], name)
	if err != nil {
		return nil, err
	}

	tval := make([]byte, len(tb))
	var i int
	for i = 0; i < len(tb)/2; i++ {
		tval[i] = tb[2*i]
	}
	val = tval[:i]
	return
}

// GetRegUnicode read value (base: ascii) from win registry
func GetRegUnicode(hkey, path, name string) (val []byte, err error) {
	var handle syscall.Handle
	switch hkey {
	case "HKLM":
	case "HKEY_LOCAL_MACHINE":
		err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ, &handle)
	case "HKCC":
	case "HKEY_CURRENT_CONFIG":
		err = syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_CONFIG, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ, &handle)
	case "HKCR":
	case "HKEY_CLASSES_ROOT":
		err = syscall.RegOpenKeyEx(syscall.HKEY_CLASSES_ROOT, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ, &handle)
	case "HKCU":
	case "HKEY_CURRENT_USER":
		err = syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ, &handle)
	case "HKU":
	case "HKEY_USERS":
		err = syscall.RegOpenKeyEx(syscall.HKEY_USERS, syscall.StringToUTF16Ptr(path), 0, syscall.KEY_READ, &handle)
	default:
		err = errors.New("Unknown HKEY: " + hkey)
		return
	}
	if err != nil {
		return
	}
	defer syscall.RegCloseKey(handle)
	var typ uint32
	var buffer [syscall.MAX_LONG_PATH]byte
	n := uint32(len(buffer))
	err = syscall.RegQueryValueEx(handle, syscall.StringToUTF16Ptr(name), nil, &typ, (*byte)(unsafe.Pointer(&buffer[0])), &n)
	if err != nil {
		return
	}
	var lastNonNull uint64
	lastNonNull = 0
	length := uint64(len(buffer))
	for i := uint64(0); i < length; i++ {
		if buffer[i] != 0x00 {
			lastNonNull = (i + 1)
		}
	}
	if lastNonNull >= length {
		lastNonNull = (length - 1)
	}
	val = buffer[:lastNonNull]
	return
}
