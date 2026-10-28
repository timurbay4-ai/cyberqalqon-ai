//go:build windows

package collect

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var lockFile = kernel.NewProc("LockFileEx")
var unlockFile = kernel.NewProc("UnlockFileEx")
var moveFile = kernel.NewProc("MoveFileExW")
var advapi = syscall.NewLazyDLL("advapi32.dll")
var convertSD = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var setSecurity = advapi.NewProc("SetFileSecurityW")

func reparse(path string) (bool, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return false, e
	}
	a, e := syscall.GetFileAttributes(p)
	return a&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0, e
}
func openSource(path string) (*os.File, error) {
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), path)
	var info syscall.ByHandleFileInformation
	if e = syscall.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		f.Close()
		return nil, Error("REPARSE_PATH_REJECTED")
	}
	if info.NumberOfLinks != 1 {
		f.Close()
		return nil, Error("HARDLINK_SOURCE_REJECTED")
	}
	return f, nil
}
func fileID(f *os.File) (string, error) {
	var i syscall.ByHandleFileInformation
	e := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &i)
	return fmt.Sprintf("windows:%08x:%08x%08x", i.VolumeSerialNumber, i.FileIndexHigh, i.FileIndexLow), e
}
func acquire(f *os.File) error {
	var ov syscall.Overlapped
	r, _, _ := lockFile.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	runtime.KeepAlive(&ov)
	if r == 0 {
		return Error("OWNER_LOCKED")
	}
	return nil
}
func release(f *os.File) {
	var ov syscall.Overlapped
	unlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	runtime.KeepAlive(&ov)
}
func replace(from, to string) error {
	a, e := syscall.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := syscall.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	r, _, e := moveFile.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)), 0x1|0x8)
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	if r == 0 {
		return e
	}
	return nil
}
func privateDir(path string) error {
	token, e := syscall.OpenCurrentProcessToken()
	if e != nil {
		return e
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return e
	}
	sid, e := user.User.Sid.String()
	if e != nil {
		return e
	}
	sddl, e := syscall.UTF16PtrFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + ")")
	if e != nil {
		return e
	}
	var sd uintptr
	r, _, e := convertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	runtime.KeepAlive(sddl)
	if r == 0 {
		return e
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	p, e := syscall.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	r, _, e = setSecurity.Call(uintptr(unsafe.Pointer(p)), 0x80000004, sd)
	runtime.KeepAlive(p)
	if r == 0 {
		return e
	}
	return nil
}
