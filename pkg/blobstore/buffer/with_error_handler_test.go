package buffer_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"github.com/buildbarn/bb-storage/internal/mock"
	"github.com/buildbarn/bb-storage/pkg/blobstore/buffer"
	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWithErrorHandlerOnACBuffers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// For AC buffers, there is no need to make a distinction
	// between operations in terms of error handling. As none of the
	// AC buffer types are lazy loading, WithErrorHandler() is
	// always capable of evaluating the ErrorHandler immediately.
	// It is therefore sufficient to only test ToByteSlice().

	t.Run("ImmediateSuccess", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().Done()

		data, err := buffer.WithErrorHandler(
			buffer.NewACBufferFromByteSlice(exampleActionResultBytes, buffer.Irreparable),
			errorHandler).ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, exampleActionResultBytes, data)
	})

	t.Run("RetriesFailed", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Network error")).
			Return(buffer.NewACBufferFromByteSlice([]byte("Hello"), buffer.Irreparable), nil)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Failed to unmarshal message: proto: can't skip unknown wire type 4")).
			Return(nil, status.Error(codes.Internal, "Maximum number of retries reached"))
		errorHandler.EXPECT().Done()

		_, err := buffer.WithErrorHandler(
			buffer.NewBufferFromError(status.Error(codes.Internal, "Network error")),
			errorHandler).ToByteSlice(1000)
		require.Equal(t, status.Error(codes.Internal, "Maximum number of retries reached"), err)
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Network error")).
			Return(buffer.NewACBufferFromByteSlice([]byte("Hello"), buffer.Irreparable), nil)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Failed to unmarshal message: proto: can't skip unknown wire type 4")).
			Return(buffer.NewACBufferFromActionResult(&exampleActionResultMessage, buffer.Irreparable), nil)
		errorHandler.EXPECT().Done()

		data, err := buffer.WithErrorHandler(
			buffer.NewBufferFromError(status.Error(codes.Internal, "Network error")),
			errorHandler).ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, exampleActionResultBytes, data)
	})
}

func TestWithErrorHandlerOnSimpleCASBuffers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Similar to the AC buffer, buffers created through
	// NewCASBufferFrom{ByteSlice,Error}() also allow for immediate
	// ErrorHandler evaluation. It is sufficient to only test
	// ToByteSlice().

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)

	t.Run("ImmediateSuccess", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().Done()

		data, err := buffer.WithErrorHandler(
			buffer.NewCASBufferFromByteSlice(digest, []byte("Hello world"), buffer.Irreparable),
			errorHandler).ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), data)
	})

	t.Run("RetriesFailed", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Network error")).
			Return(buffer.NewCASBufferFromByteSlice(digest, []byte("Hello"), buffer.Irreparable), nil)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Buffer is 5 bytes in size, while 11 bytes were expected")).
			Return(nil, status.Error(codes.Internal, "Maximum number of retries reached"))
		errorHandler.EXPECT().Done()

		_, err := buffer.WithErrorHandler(
			buffer.NewBufferFromError(status.Error(codes.Internal, "Network error")),
			errorHandler).ToByteSlice(1000)
		require.Equal(t, status.Error(codes.Internal, "Maximum number of retries reached"), err)
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Network error")).
			Return(buffer.NewCASBufferFromByteSlice(digest, []byte("Hello"), buffer.Irreparable), nil)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Buffer is 5 bytes in size, while 11 bytes were expected")).
			Return(buffer.NewCASBufferFromByteSlice(digest, []byte("Hello world"), buffer.Irreparable), nil)
		errorHandler.EXPECT().Done()

		data, err := buffer.WithErrorHandler(
			buffer.NewBufferFromError(status.Error(codes.Internal, "Network error")),
			errorHandler).ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), data)
	})
}

func TestWithErrorHandlerOnCASBuffersIntoWriter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)

	t.Run("RetriesFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(nil, status.Error(codes.Internal, "No backends available"))
		errorHandler.EXPECT().Done()

		writer := bytes.NewBuffer(nil)
		err := buffer.WithErrorHandler(b1, errorHandler).IntoWriter(writer)
		require.Equal(t, status.Error(codes.Internal, "No backends available"), err)
		require.Equal(t, []byte("Hello "), writer.Bytes())
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		reader2 := ioutil.NopCloser(bytes.NewBufferString("XXXXXXworld"))
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// The start of the second stream is discarded, as the
		// first stream was already written to the output. Data
		// corruption within a part of the stream that is
		// already written is not a problem.
		writer := bytes.NewBuffer(nil)
		err := buffer.WithErrorHandler(b1, errorHandler).IntoWriter(writer)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), writer.Bytes())
	})

	t.Run("ChecksumFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Xyzzy "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		repairFunc1 := mock.NewMockRepairFunc(ctrl)
		repairFunc1.EXPECT().Call().Return(nil)
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Reparable(digest, repairFunc1.Call))

		reader2 := ioutil.NopCloser(bytes.NewBufferString("Hello world"))
		repairFunc2 := mock.NewMockRepairFunc(ctrl)
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Reparable(digest, repairFunc2.Call))

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// Merging the two streams will cause "Xyzzy world" to
		// be returned. This causes a checksum failure. There is
		// no way to recover from this, because we've already
		// written a part of the corrupted data into the output
		// stream.
		writer := bytes.NewBuffer(nil)
		err := buffer.WithErrorHandler(b1, errorHandler).IntoWriter(writer)
		require.Equal(t, status.Error(codes.Internal, "Buffer has checksum 3c61ab3f7343f99e0d18e0a7dfb3b0ce, while 3e25960a79dbc69b674cd4ec67a72c62 was expected"), err)
		require.Equal(t, []byte("Xyzzy "), writer.Bytes())
	})
}

// Only provide simple testing coverage for ReadAt(). It is built on top
// of exactly the same retry logic as ToActionResult().
func TestWithErrorHandlerOnCASBuffersReadAt(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reader1 := mock.NewMockReadCloser(ctrl)
	reader1.EXPECT().Read(gomock.Any()).Return(0, status.Error(codes.Internal, "Connection closed"))
	reader1.EXPECT().Close().Return(nil)
	b1 := buffer.NewCASBufferFromReader(exampleActionResultDigest, reader1, buffer.Irreparable)
	b2 := buffer.NewValidatedBufferFromByteSlice([]byte("Hello world"))

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
	errorHandler.EXPECT().Done()

	var b [2]byte
	n, err := buffer.WithErrorHandler(b1, errorHandler).ReadAt(b[:], 2)
	require.Equal(t, 2, n)
	require.NoError(t, err)
}

func TestWithErrorHandlerOnCASBuffersToActionResult(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("RetriesFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return(exampleActionResultBytes[:10], nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(exampleActionResultDigest, reader1, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(nil, status.Error(codes.Internal, "No backends available"))
		errorHandler.EXPECT().Done()

		_, err := buffer.WithErrorHandler(b1, errorHandler).ToActionResult(10000)
		require.Equal(t, status.Error(codes.Internal, "No backends available"), err)
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		reader1 := mock.NewMockReadCloser(ctrl)
		reader1.EXPECT().Read(gomock.Any()).Return(0, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close().Return(nil)
		b1 := buffer.NewCASBufferFromReader(exampleActionResultDigest, reader1, buffer.Irreparable)

		reader2 := mock.NewMockChunkReader(ctrl)
		reader2.EXPECT().Read().Return(exampleActionResultBytes, nil)
		reader2.EXPECT().Read().Return(nil, io.EOF)
		reader2.EXPECT().Close()
		b2 := buffer.NewCASBufferFromChunkReader(exampleActionResultDigest, reader2, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		actionResult, err := buffer.WithErrorHandler(b1, errorHandler).ToActionResult(10000)
		require.NoError(t, err)
		require.True(t, proto.Equal(&exampleActionResultMessage, actionResult))
	})

	t.Run("ChecksumFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello"), nil)
		reader1.EXPECT().Read().Return(nil, io.EOF)
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(exampleActionResultDigest, reader1, buffer.Irreparable)

		reader2 := mock.NewMockChunkReader(ctrl)
		reader2.EXPECT().Read().Return(exampleActionResultBytes, nil)
		reader2.EXPECT().Read().Return(nil, io.EOF)
		reader2.EXPECT().Close()
		b2 := buffer.NewCASBufferFromChunkReader(exampleActionResultDigest, reader2, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Buffer is 5 bytes in size, while 134 bytes were expected")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// Operations like ToActionResult() may be safely
		// retried, even in the case of data inconsistency
		// errors. The call should succeed, even if it obtained
		// invalid data initially.
		actionResult, err := buffer.WithErrorHandler(b1, errorHandler).ToActionResult(10000)
		require.NoError(t, err)
		require.True(t, proto.Equal(&exampleActionResultMessage, actionResult))
	})
}

// Only provide simple testing coverage for ToByteSlice(). It is built on top
// of exactly the same retry logic as ToActionResult().
func TestWithErrorHandlerOnCASBuffersToByteSlice(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	reader1 := mock.NewMockReadCloser(ctrl)
	reader1.EXPECT().Read(gomock.Any()).Return(0, status.Error(codes.Internal, "Connection closed"))
	reader1.EXPECT().Close().Return(nil)
	b1 := buffer.NewCASBufferFromReader(exampleActionResultDigest, reader1, buffer.Irreparable)
	b2 := buffer.NewValidatedBufferFromByteSlice([]byte("Hello world"))

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
	errorHandler.EXPECT().Done()

	data, err := buffer.WithErrorHandler(b1, errorHandler).ToByteSlice(1000)
	require.NoError(t, err)
	require.Equal(t, []byte("Hello world"), data)
}

func TestWithErrorHandlerOnCASBuffersToChunkReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)

	t.Run("RetriesFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(nil, status.Error(codes.Internal, "No backends available"))
		errorHandler.EXPECT().Done()

		r := buffer.WithErrorHandler(b1, errorHandler).ToChunkReader(
			/* offset = */ 2,
			/* chunk size = */ 10)
		chunk, err := r.Read()
		require.NoError(t, err)
		require.Equal(t, []byte("llo "), chunk)
		_, err = r.Read()
		require.Equal(t, status.Error(codes.Internal, "No backends available"), err)
		r.Close()
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		reader2 := ioutil.NopCloser(bytes.NewBufferString("XXXXXXworld"))
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// The start of the second stream is discarded, as the
		// first stream was already written to the output. Data
		// corruption within a part of the stream that is
		// already written is not a problem.
		r := buffer.WithErrorHandler(b1, errorHandler).ToChunkReader(
			/* offset = */ 4,
			/* chunk size = */ 3)
		chunk, err := r.Read()
		require.NoError(t, err)
		require.Equal(t, []byte("o "), chunk)
		chunk, err = r.Read()
		require.NoError(t, err)
		require.Equal(t, []byte("wor"), chunk)
		chunk, err = r.Read()
		require.NoError(t, err)
		require.Equal(t, []byte("ld"), chunk)
		_, err = r.Read()
		require.Equal(t, io.EOF, err)
		r.Close()
	})

	t.Run("ChecksumFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Xyzzy "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		repairFunc1 := mock.NewMockRepairFunc(ctrl)
		repairFunc1.EXPECT().Call().Return(nil)
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Reparable(digest, repairFunc1.Call))

		reader2 := ioutil.NopCloser(bytes.NewBufferString("Hello world"))
		repairFunc2 := mock.NewMockRepairFunc(ctrl)
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Reparable(digest, repairFunc2.Call))

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// Merging the two streams will cause "Xyzzy world" to
		// be returned. This causes a checksum failure. There is
		// no way to recover from this, because we've already
		// written a part of the corrupted data into the output
		// stream.
		r := buffer.WithErrorHandler(b1, errorHandler).ToChunkReader(
			/* offset = */ 0,
			/* chunk size = */ 1000)
		chunk, err := r.Read()
		require.NoError(t, err)
		require.Equal(t, []byte("Xyzzy "), chunk)
		_, err = r.Read()
		require.Equal(t, status.Error(codes.Internal, "Buffer has checksum 3c61ab3f7343f99e0d18e0a7dfb3b0ce, while 3e25960a79dbc69b674cd4ec67a72c62 was expected"), err)
		r.Close()
	})
}

func TestWithErrorHandlerOnCASBuffersToReader(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)

	t.Run("RetriesFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(nil, status.Error(codes.Internal, "No backends available"))
		errorHandler.EXPECT().Done()

		r := buffer.WithErrorHandler(b1, errorHandler).ToReader()
		_, err := ioutil.ReadAll(r)
		require.Equal(t, status.Error(codes.Internal, "No backends available"), err)
		require.NoError(t, r.Close())
	})

	t.Run("RetriesSuccess", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Hello "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Irreparable)

		reader2 := ioutil.NopCloser(bytes.NewBufferString("XXXXXXworld"))
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Irreparable)

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// The start of the second stream is discarded, as the
		// first stream was already written to the output. Data
		// corruption within a part of the stream that is
		// already written is not a problem.
		r := buffer.WithErrorHandler(b1, errorHandler).ToReader()
		data, err := ioutil.ReadAll(r)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), data)
		require.NoError(t, r.Close())
	})

	t.Run("ChecksumFailure", func(t *testing.T) {
		reader1 := mock.NewMockChunkReader(ctrl)
		reader1.EXPECT().Read().Return([]byte("Xyzzy "), nil)
		reader1.EXPECT().Read().Return(nil, status.Error(codes.Internal, "Connection closed"))
		reader1.EXPECT().Close()
		repairFunc1 := mock.NewMockRepairFunc(ctrl)
		repairFunc1.EXPECT().Call().Return(nil)
		b1 := buffer.NewCASBufferFromChunkReader(digest, reader1, buffer.Reparable(digest, repairFunc1.Call))

		reader2 := ioutil.NopCloser(bytes.NewBufferString("Hello world"))
		repairFunc2 := mock.NewMockRepairFunc(ctrl)
		b2 := buffer.NewCASBufferFromReader(digest, reader2, buffer.Reparable(digest, repairFunc2.Call))

		errorHandler := mock.NewMockErrorHandler(ctrl)
		errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
		errorHandler.EXPECT().Done()

		// Merging the two streams will cause "Xyzzy world" to
		// be returned. This causes a checksum failure. There is
		// no way to recover from this, because we've already
		// written a part of the corrupted data into the output
		// stream.
		r := buffer.WithErrorHandler(b1, errorHandler).ToReader()
		data, err := ioutil.ReadAll(r)
		require.Equal(t, status.Error(codes.Internal, "Buffer has checksum 3c61ab3f7343f99e0d18e0a7dfb3b0ce, while 3e25960a79dbc69b674cd4ec67a72c62 was expected"), err)
		require.Equal(t, []byte("Xyzzy "), data)
		require.NoError(t, r.Close())
	})
}

// Only provide simple testing coverage for CloneCopy(). It is built on
// top of ToByteSlice().
func TestWithErrorHandlerOnCASBuffersCloneCopy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)
	reader1 := mock.NewMockReadCloser(ctrl)
	reader1.EXPECT().Read(gomock.Any()).Return(0, status.Error(codes.Internal, "Connection closed"))
	reader1.EXPECT().Close().Return(nil)
	b1 := buffer.NewCASBufferFromReader(digest, reader1, buffer.Irreparable)
	b2 := buffer.NewValidatedBufferFromByteSlice([]byte("Hello world"))

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
	errorHandler.EXPECT().Done()

	bc1, bc2 := buffer.WithErrorHandler(b1, errorHandler).CloneCopy(1000)

	data1, err := bc1.ToByteSlice(1000)
	require.NoError(t, err)
	require.Equal(t, []byte("Hello world"), data1)

	data2, err := bc2.ToByteSlice(1000)
	require.NoError(t, err)
	require.Equal(t, []byte("Hello world"), data2)
}

func TestWithErrorHandlerOnCASBuffersCloneStream(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	digest := digest.MustNewDigest("instance", "3e25960a79dbc69b674cd4ec67a72c62", 11)
	reader1 := mock.NewMockReadCloser(ctrl)
	reader1.EXPECT().Read(gomock.Any()).Return(0, status.Error(codes.Internal, "Connection closed"))
	reader1.EXPECT().Close().Return(nil)
	b1 := buffer.NewCASBufferFromReader(digest, reader1, buffer.Irreparable)
	b2 := buffer.NewValidatedBufferFromByteSlice([]byte("Hello world"))

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Connection closed")).Return(b2, nil)
	errorHandler.EXPECT().Done()

	bc1, bc2 := buffer.WithErrorHandler(b1, errorHandler).CloneStream()
	done := make(chan struct{}, 2)

	go func() {
		data, err := bc1.ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), data)
		done <- struct{}{}
	}()

	go func() {
		data, err := bc2.ToByteSlice(1000)
		require.NoError(t, err)
		require.Equal(t, []byte("Hello world"), data)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func TestWithErrorHandlerOnCASBuffersDiscard(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	chunkReader := mock.NewMockChunkReader(ctrl)
	chunkReader.EXPECT().Close()
	repairFunc := mock.NewMockRepairFunc(ctrl)
	b1 := buffer.NewCASBufferFromChunkReader(exampleDigest, chunkReader, buffer.Reparable(exampleDigest, repairFunc.Call))

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().Done()

	buffer.WithErrorHandler(b1, errorHandler).Discard()
}

func TestWithErrorHandlerOnClonedErrorBuffer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	errorHandler := mock.NewMockErrorHandler(ctrl)
	errorHandler.EXPECT().OnError(status.Error(codes.Internal, "Error message A")).Return(nil, status.Error(codes.Internal, "Error message B"))
	errorHandler.EXPECT().Done()

	b1, b2 := buffer.NewBufferFromError(status.Error(codes.Internal, "Error message A")).CloneCopy(100)
	b2 = buffer.WithErrorHandler(b2, errorHandler)

	// The first consumer will get access to the original error message.
	_, err := b1.ToByteSlice(100)
	require.Equal(t, status.Error(codes.Internal, "Error message A"), err)

	// The second consumer will have the error message replaced.
	_, err = b2.ToByteSlice(100)
	require.Equal(t, status.Error(codes.Internal, "Error message B"), err)
}
