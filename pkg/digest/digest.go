package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"path"
	"strconv"
	"strings"

	remoteexecution "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	"github.com/buildbarn/bb-storage/pkg/util"
	"github.com/google/uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Digest holds the identification of an object stored in the Content
// Addressable Storage (CAS) or Action Cache (AC). The use of this
// object is preferred over remoteexecution.Digest for a couple of
// reasons.
//
// - Instances of these objects are guaranteed not to contain any
//   degenerate values. The hash has already been decoded from
//   hexadecimal to binary. The size is non-negative.
// - They keep track of the instance as part of the digest, which allows
//   us to keep function signatures across the codebase simple.
// - They provide utility functions for deriving new digests from them.
//   This ensures that outputs of build actions automatically use the
//   same instance name and hashing algorithm.
//
// Because Digest objects are frequently used as keys (as part of
// caching data structures or to construct sets without duplicate
// values), this implementation immediately constructs a key
// representation upon creation. All functions that extract individual
// components (e.g., GetInstanceName(), GetHash*() and GetSizeBytes())
// operate directly on the key format.
type Digest struct {
	value string
}

// BadDigest is a default instance of Digest. It can, for example, be
// used as a function return value for error cases.
var BadDigest Digest

// SupportedDigestFunctions is the list of digest functions supported by
// digest.Digest, using the enumeration values that are part of the
// Remote Execution protocol.
var SupportedDigestFunctions = []remoteexecution.DigestFunction_Value{
	remoteexecution.DigestFunction_BLAKE3ZCC,
	remoteexecution.DigestFunction_MD5,
	remoteexecution.DigestFunction_SHA1,
	remoteexecution.DigestFunction_SHA256,
	remoteexecution.DigestFunction_SHA384,
	remoteexecution.DigestFunction_SHA512,
}

// Unpack the individual hash, size and instance name fields from the
// string representation stored inside the Digest object.
func (d Digest) unpack() (int, int64, int) {
	// Extract the leading hash.
	hashEnd := md5.Size * 2
	for d.value[hashEnd] != '-' {
		hashEnd++
	}

	// Extract the size stored in the middle.
	sizeBytes := int64(0)
	sizeBytesEnd := hashEnd + 1
	for d.value[sizeBytesEnd] != '-' {
		sizeBytes = sizeBytes*10 + int64(d.value[sizeBytesEnd]-'0')
		sizeBytesEnd++
	}

	return hashEnd, sizeBytes, sizeBytesEnd
}

// MustNewDigest constructs a Digest similar to NewDigest, but never
// returns an error. Instead, execution will abort if the resulting
// instance would be degenerate. Useful for unit testing.
func MustNewDigest(instanceName, hash string, sizeBytes int64) Digest {
	in, err := NewInstanceName(instanceName)
	if err != nil {
		panic(err)
	}
	d, err := in.NewDigest(hash, sizeBytes)
	if err != nil {
		panic(err)
	}
	return d
}

// NewDigestFromByteStreamReadPath creates a Digest from a string having
// the following format: ${instanceName}/blobs/${hash}/${size}. This
// notation is used to read files through the ByteStream service.
func NewDigestFromByteStreamReadPath(path string) (Digest, error) {
	fields := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(fields) < 3 {
		return BadDigest, status.Error(codes.InvalidArgument, "Invalid resource naming scheme")
	}
	split := len(fields) - 3
	return newDigestFromByteStreamPathCommon(fields[:split], fields[split:])
}

// NewDigestFromByteStreamWritePath creates a Digest from a string
// having the following format:
// ${instanceName}/uploads/${uuid}/blobs/${hash}/${size}/${path}. This
// notation is used to write files through the ByteStream service.
func NewDigestFromByteStreamWritePath(path string) (Digest, error) {
	fields := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	if len(fields) < 5 {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid resource naming scheme")
	}
	// Determine the end of the instance name. Because both the
	// leading instance name and the trailing path have a variable
	// length, this may be ambiguous. This is why instance names are
	// not permitted to contain "uploads" pathname components.
	split := 0
	for fields[split] != "uploads" {
		split++
		if split > len(fields)-5 {
			return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid resource naming scheme")
		}
	}
	return newDigestFromByteStreamPathCommon(fields[:split], fields[split+2:])
}

func newDigestFromByteStreamPathCommon(header, trailer []string) (Digest, error) {
	if trailer[0] != "blobs" {
		return BadDigest, status.Error(codes.InvalidArgument, "Invalid resource naming scheme")
	}
	sizeBytes, err := strconv.ParseInt(trailer[2], 10, 64)
	if err != nil {
		return BadDigest, status.Errorf(codes.InvalidArgument, "Invalid blob size %#v", trailer[2])
	}
	instanceName, err := NewInstanceNameFromComponents(header)
	if err != nil {
		return BadDigest, util.StatusWrapf(err, "Invalid instance name %#v", strings.Join(header, "/"))
	}
	return instanceName.NewDigest(trailer[1], sizeBytes)
}

// GetByteStreamReadPath converts the Digest to a string having
// the following format: ${instanceName}/blobs/${hash}/${size}. This
// notation is used to read files through the ByteStream service.
func (d Digest) GetByteStreamReadPath() string {
	hashEnd, sizeBytes, sizeBytesEnd := d.unpack()
	return path.Join(
		d.value[sizeBytesEnd+1:],
		"blobs",
		d.value[:hashEnd],
		strconv.FormatInt(sizeBytes, 10))
}

// GetByteStreamWritePath converts the Digest to a string having the
// following format:
// ${instanceName}/uploads/${uuid}/blobs/${hash}/${size}/${path}. This
// notation is used to write files through the ByteStream service.
func (d Digest) GetByteStreamWritePath(uuid uuid.UUID) string {
	hashEnd, sizeBytes, sizeBytesEnd := d.unpack()
	return path.Join(
		d.value[sizeBytesEnd+1:],
		"uploads",
		uuid.String(),
		"blobs",
		d.value[:hashEnd],
		strconv.FormatInt(sizeBytes, 10))
}

// GetProto encodes the digest into the format used by the remote
// execution protocol, so that it may be stored in messages returned to
// the client.
func (d Digest) GetProto() *remoteexecution.Digest {
	hashEnd, sizeBytes, _ := d.unpack()
	hash := d.value[:hashEnd]
	if strings.HasPrefix(hash, "B3Z:") {
		hashBytes, err := hex.DecodeString(hash[4:])
		if err != nil {
			panic("Failed to decode malformed BLAKE3ZCC hash")
		}
		return &remoteexecution.Digest{
			HashBlake3Zcc: hashBytes,
			SizeBytes:     sizeBytes,
		}
	}
	if strings.HasPrefix(hash, "B3ZM:") {
		hashBytes, err := hex.DecodeString(hash[5:])
		if err != nil {
			panic("Failed to decode malformed BLAKE3ZCC manifest hash")
		}
		return &remoteexecution.Digest{
			HashBlake3ZccManifest: hashBytes,
			SizeBytes:             sizeBytes,
		}
	}
	return &remoteexecution.Digest{
		HashOther: hash,
		SizeBytes: sizeBytes,
	}
}

// GetInstanceName returns the instance name of the object.
func (d Digest) GetInstanceName() InstanceName {
	_, _, sizeBytesEnd := d.unpack()
	return InstanceName{
		value: d.value[sizeBytesEnd+1:],
	}
}

// GetHashBytes returns the hash of the object as a slice of bytes.
func (d Digest) GetHashBytes() []byte {
	hashString := d.GetHashString()
	if strings.HasPrefix(hashString, "B3Z:") {
		hashString = hashString[4:]
	}
	if strings.HasPrefix(hashString, "B3ZM:") {
		hashString = hashString[5:]
	}
	hashBytes, err := hex.DecodeString(hashString)
	if err != nil {
		panic("Failed to decode digest hash, even though its contents have already been validated")
	}
	return hashBytes
}

// GetHashString returns the hash of the object as a string.
func (d Digest) GetHashString() string {
	hashEnd, _, _ := d.unpack()
	return d.value[:hashEnd]
}

// GetSizeBytes returns the size of the object, in bytes.
func (d Digest) GetSizeBytes() int64 {
	_, sizeBytes, _ := d.unpack()
	return sizeBytes
}

// KeyFormat is an enumeration type that determines the format of object
// keys returned by Digest.GetKey().
type KeyFormat int

// Combine two KeyFormats into one, picking the format that contains the
// most information.
//
// This function is used extensively by NewBlobAccessFromConfiguration()
// to ensure that the right KeyFormat is picked based on the behavior of
// two or more backing BlobAccess instances.
func (kf KeyFormat) Combine(other KeyFormat) KeyFormat {
	if kf == KeyWithInstance {
		return KeyWithInstance
	}
	return other
}

const (
	// KeyWithoutInstance lets Digest.GetKey() return a key that
	// does not include the name of the instance; only the hash and
	// the size.
	KeyWithoutInstance KeyFormat = iota
	// KeyWithInstance lets Digest.GetKey() return a key that
	// includes the hash, size and instance name.
	KeyWithInstance
)

// GetKey generates a string representation of the digest object that
// may be used as keys in hash tables.
func (d Digest) GetKey(format KeyFormat) string {
	switch format {
	case KeyWithoutInstance:
		_, _, sizeBytesEnd := d.unpack()
		return d.value[:sizeBytesEnd]
	case KeyWithInstance:
		return d.value
	default:
		panic("Invalid digest key format")
	}
}

func (d Digest) String() string {
	return d.GetKey(KeyWithInstance)
}

// ToSingletonSet creates a Set that contains a single element that
// corresponds to the Digest.
func (d Digest) ToSingletonSet() Set {
	return Set{
		digests: []Digest{d},
	}
}

func convertSizeToBlockCount(blobSizeBytes int64, blockSizeBytes int64) int64 {
	return int64((uint64(blobSizeBytes) + uint64(blockSizeBytes) - 1) / uint64(blockSizeBytes))
}

// ToManifest converts a digest object to the digest of its manifest
// object counterpart. Summaries allow large objects to be decomposed
// into a series of concatenate blocks. Manifest objects are stored in
// the CAS as a sequence of digests of their chunks.
//
// It is only possible to create manifest objects when VSO hashing is
// used. This implementation only allows the creation of manifest objects
// for blobs larger than a single block (2 MiB), as storing summaries
// for single block objects would be wasteful.
//
// In addition to returning the digest of the manifest object, this
// function returns a ManifestParser that may be used to extract digests
// from existing summaries or insert digests into new summaries.
func (d Digest) ToManifest(blockSizeBytes int64) (Digest, ManifestParser, bool) {
	if !strings.HasPrefix(d.value, "B3Z:") {
		return BadDigest, nil, false
	}

	// TODO: Check that blockSizeBytes is valid!

	hashEnd, sizeBytes, sizeBytesEnd := d.unpack()
	if sizeBytes <= blockSizeBytes {
		return BadDigest, nil, false
	}

	manifestSizeBytes := convertSizeToBlockCount(sizeBytes, blockSizeBytes) * blake3zccParentNodeSizeBytes
	if lastBlockSizeBytes := sizeBytes % blockSizeBytes; lastBlockSizeBytes > 0 && lastBlockSizeBytes <= 1024 {
		manifestSizeBytes += blake3zccChunkNodeSizeBytes - blake3zccParentNodeSizeBytes
	}
	hash := d.value[4:hashEnd]
	instance := d.value[sizeBytesEnd+1:]
	return Digest{
			value: fmt.Sprintf(
				"B3ZM:%s-%d-%s",
				hash,
				manifestSizeBytes,
				instance),
		},
		newBLAKE3ZCCManifestParser(instance, sizeBytes, blockSizeBytes, len(hash)/2),
		true
}

func getHasherFactory(hashLength int) func() hash.Hash {
	switch hashLength {
	case md5.Size * 2:
		return md5.New
	case sha1.Size * 2:
		return sha1.New
	case sha256.Size * 2:
		return sha256.New
	case sha512.Size384 * 2:
		return sha512.New384
	case sha512.Size * 2:
		return sha512.New
	default:
		panic("Digest hash is of unknown type")
	}
}

// NewHasher creates a standard hash.Hash object that may be used to
// compute a checksum of data. The hash.Hash object uses the same
// algorithm as the one that was used to create the digest, making it
// possible to validate data against a digest.
func (d Digest) NewHasher() hash.Hash {
	hash := d.GetHashString()
	if strings.HasPrefix(hash, "B3Z:") {
		return newBLAKE3ZCCBlobHasher(len(hash[4:]) / 2)
	}
	if strings.HasPrefix(hash, "B3ZM:") {
		return newBLAKE3ZCCManifestHasher(len(hash[5:]) / 2)
	}
	hashEnd, _, _ := d.unpack()
	return getHasherFactory(hashEnd)()
}

// GetDigestFunction returns a Function object that can be used to
// generate new Digest objects that use the same instance name and
// hashing algorithm. This method can be used in case new digests need
// to be derived based on an existing instance. For example, to generate
// a digest of an output file of a build action, given an action digest.
func (d Digest) GetDigestFunction() Function {
	hashEnd, _, sizeBytesEnd := d.unpack()
	return Function{
		instanceName: InstanceName{
			value: d.value[sizeBytesEnd+1:],
		},
		hasherFactory: getHasherFactory(hashEnd),
		hashLength:    hashEnd,
	}
}

// UsesDigestFunction returns true iff a Digest has the same instance
// name and uses the same hashing algorithm as a provided Function
// object.
func (d Digest) UsesDigestFunction(f Function) bool {
	hashEnd, _, sizeBytesEnd := d.unpack()
	return hashEnd == f.hashLength && d.value[sizeBytesEnd+1:] == f.instanceName.value
}
