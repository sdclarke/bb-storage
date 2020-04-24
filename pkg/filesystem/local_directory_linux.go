// +build linux

package filesystem

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// deviceNumber is the equivalent of POSIX dev_t.
type deviceNumber = uint64

func (d *localDirectory) Mknod(name string, perm os.FileMode, dev int) error {
	if err := validateFilename(name); err != nil {
		return err
	}
	defer runtime.KeepAlive(d)

	return unix.Mknodat(d.fd, name, uint32(perm), dev)
}
