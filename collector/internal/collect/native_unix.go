//go:build !windows

package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func reparse(p string) (bool, error) {
	i, e := os.Lstat(p)
	if e != nil {
		return false, e
	}
	return i.Mode()&os.ModeSymlink != 0, nil
}
func openSource(p string) (*os.File, error) {
	f, e := os.Open(p)
	if e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Nlink != 1 {
		f.Close()
		return nil, Error("HARDLINK_SOURCE_REJECTED")
	}
	return f, nil
}
func fileID(f *os.File) (string, error) {
	i, e := f.Stat()
	if e != nil {
		return "", e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return "", Error("FILE_ID_UNAVAILABLE")
	}
	return fmt.Sprintf("posix:%x:%x", s.Dev, s.Ino), nil
}
func acquire(f *os.File) error {
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Error("OWNER_LOCKED")
	}
	return nil
}
func release(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
func replace(a, b string) error {
	if e := os.Rename(a, b); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(b))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func privateDir(p string) error { return os.Chmod(p, 0700) }
