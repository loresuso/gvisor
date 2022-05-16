// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vfs2

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Getdents implements Linux syscall getdents(2).
func Getdents(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, false /* isGetdents64 */)
}

// Getdents64 implements Linux syscall getdents64(2).
func Getdents64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, true /* isGetdents64 */)
}

func getdents(t *kernel.Task, args arch.SyscallArguments, isGetdents64 bool) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := int(args[2].Uint())

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	cb := getGetdentsCallback(t, size, isGetdents64)
	err := file.IterDirents(t, cb)
	if err != nil && cb.copied == 0 {
		putGetdentsCallback(cb)
		return 0, nil, err
	}
	n, err := t.CopyOutBytes(addr, cb.buf[:cb.copied])
	putGetdentsCallback(cb)

	return uintptr(n), nil, err
}

type getdentsCallback struct {
	t            *kernel.Task
	buf          []byte
	copied       int
	isGetdents64 bool
}

var getdentsCallbackPool = sync.Pool{
	New: func() interface{} {
		return &getdentsCallback{}
	},
}

func getGetdentsCallback(t *kernel.Task, size int, isGetdents64 bool) *getdentsCallback {
	cb := getdentsCallbackPool.Get().(*getdentsCallback)
	buf := cb.buf
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}

	*cb = getdentsCallback{
		t:            t,
		buf:          buf,
		copied:       0,
		isGetdents64: isGetdents64,
	}
	return cb
}

func putGetdentsCallback(cb *getdentsCallback) {
	cb.t = nil
	cb.buf = cb.buf[:0]
	getdentsCallbackPool.Put(cb)
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (cb *getdentsCallback) Handle(dirent vfs.Dirent) error {
	remaining := len(cb.buf) - cb.copied
	if cb.isGetdents64 {
		// struct linux_dirent64 {
		//     ino64_t        d_ino;    /* 64-bit inode number */
		//     off64_t        d_off;    /* 64-bit offset to next structure */
		//     unsigned short d_reclen; /* Size of this dirent */
		//     unsigned char  d_type;   /* File type */
		//     char           d_name[]; /* Filename (null-terminated) */
		// };
		size := 8 + 8 + 2 + 1 + 1 + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of 8
		if size > remaining {
			return linuxerr.EINVAL
		}
		buf := cb.buf[cb.copied : cb.copied+size]
		hostarch.ByteOrder.PutUint64(buf[0:8], dirent.Ino)
		hostarch.ByteOrder.PutUint64(buf[8:16], uint64(dirent.NextOff))
		hostarch.ByteOrder.PutUint16(buf[16:18], uint16(size))
		buf[18] = dirent.Type
		copy(buf[19:], dirent.Name)
		// Zero out all remaining bytes in buf, including the NUL terminator
		// after dirent.Name.
		bufTail := buf[19+len(dirent.Name):]
		for i := range bufTail {
			bufTail[i] = 0
		}
		cb.copied += size
	} else {
		// struct linux_dirent {
		//     unsigned long  d_ino;     /* Inode number */
		//     unsigned long  d_off;     /* Offset to next linux_dirent */
		//     unsigned short d_reclen;  /* Length of this linux_dirent */
		//     char           d_name[];  /* Filename (null-terminated) */
		//                       /* length is actually (d_reclen - 2 -
		//                          offsetof(struct linux_dirent, d_name)) */
		//     /*
		//     char           pad;       // Zero padding byte
		//     char           d_type;    // File type (only since Linux
		//                               // 2.6.4); offset is (d_reclen - 1)
		//     */
		// };
		if cb.t.Arch().Width() != 8 {
			panic(fmt.Sprintf("unsupported sizeof(unsigned long): %d", cb.t.Arch().Width()))
		}
		size := 8 + 8 + 2 + 1 + 1 + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of sizeof(long)
		if size > remaining {
			return linuxerr.EINVAL
		}
		buf := cb.buf[cb.copied : cb.copied+size]
		hostarch.ByteOrder.PutUint64(buf[0:8], dirent.Ino)
		hostarch.ByteOrder.PutUint64(buf[8:16], uint64(dirent.NextOff))
		hostarch.ByteOrder.PutUint16(buf[16:18], uint16(size))
		copy(buf[18:], dirent.Name)
		// Zero out all remaining bytes in buf, including the NUL terminator
		// after dirent.Name and the zero padding byte between the name and
		// dirent type.
		bufTail := buf[18+len(dirent.Name) : size-1]
		for i := range bufTail {
			bufTail[i] = 0
		}
		buf[size-1] = dirent.Type
		cb.copied += size
	}

	return nil
}
