package filesystem

import (
	"io"
	"time"
)

var (
	// DeterministicFileModificationTimestamp is a fixed timestamp set to
	// 2000-01-01 00:00:00
	DeterministicFileModificationTimestamp = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// FileAppender is returned by Directory.OpenAppend(). It is a handle
// for a file that only permits new data to be written to the end.
type FileAppender interface {
	io.Closer
	io.Writer
}

// FileReader is returned by Directory.OpenRead(). It is a handle
// for a file that permits data to be read from arbitrary locations.
type FileReader interface {
	io.Closer
	io.ReaderAt
}

// FileReadWriter is returned by Directory.OpenReadWrite(). It is a
// handle for a file that permits data to be read from and written to
// arbitrary locations.
type FileReadWriter interface {
	io.Closer
	io.ReaderAt
	io.WriterAt

	Truncate(size int64) error
}

// FileWriter is returned by Directory.OpenWrite(). It is a handle for a
// file that permits data to be written to arbitrary locations.
type FileWriter interface {
	io.Closer
	io.WriterAt

	Truncate(size int64) error
}
