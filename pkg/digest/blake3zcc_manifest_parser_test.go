package digest_test

import (
	"testing"

	"github.com/buildbarn/bb-storage/pkg/digest"
	"github.com/stretchr/testify/require"
)

func TestBLAKE3ZCCManifestParserGetBlockDigest(t *testing.T) {
	// Construct a ManifestParser for an object consisting of three
	// blocks.
	// TODO: Use the right checksum in the example!
	blobDigest := digest.MustNewDigest(
		"instance",
		"B3Z:4c522509f3e722ad893600907cbd2fa85bb8cc49ab945e76289bb71f4c3322d6",
		5121)
	manifestDigest, manifestParser, ok := blobDigest.ToManifest(2048)
	require.True(t, ok)
	require.Equal(
		t,
		digest.MustNewDigest(
			"instance",
			"B3ZM:4c522509f3e722ad893600907cbd2fa85bb8cc49ab945e76289bb71f4c3322d6",
			192),
		manifestDigest)

	// The manifest that corresponds to the digest above.
	manifest := []byte{
		// First block.
		0x85, 0xc0, 0xcb, 0x88, 0xd6, 0x53, 0x9c, 0xf7, 0x69, 0xa3, 0x1e, 0x9f, 0x5e, 0xef, 0x7a, 0x28,
		0xc7, 0x85, 0x23, 0xad, 0xf4, 0xaf, 0x0b, 0xb2, 0xa1, 0x52, 0x32, 0xf8, 0xc3, 0x72, 0x2b, 0xd4,
		0x80, 0x88, 0x1f, 0x28, 0x90, 0x79, 0xda, 0x9d, 0x93, 0x86, 0xca, 0x73, 0xf8, 0x02, 0xe2, 0x98,
		0x58, 0x7d, 0x01, 0xda, 0x6e, 0xaa, 0xb3, 0x86, 0x26, 0x3b, 0xa8, 0x72, 0x3c, 0x7f, 0xeb, 0x8e,
		// Second block.
		0x42, 0x8a, 0x21, 0x1e, 0x79, 0x2b, 0xc0, 0xbe, 0x74, 0xe7, 0x01, 0x1b, 0x0a, 0xd2, 0x9b, 0x4f,
		0xc7, 0x83, 0x9c, 0xce, 0x6a, 0x07, 0x75, 0xad, 0x6b, 0x68, 0x5d, 0x96, 0x51, 0xe6, 0x20, 0xe4,
		0x18, 0xa8, 0x65, 0xf1, 0xd2, 0x3c, 0x1a, 0xee, 0xe4, 0xc5, 0x4e, 0x7e, 0x20, 0xea, 0xb6, 0x5a,
		0xe6, 0xbe, 0x08, 0x8b, 0x57, 0x26, 0x13, 0xbf, 0x84, 0xa8, 0xf7, 0xa8, 0xe7, 0x61, 0x8c, 0x05,
		// Third block.
		0x26, 0x3d, 0xee, 0xfa, 0xfa, 0x11, 0xfb, 0x04, 0x11, 0x11, 0xa4, 0x61, 0xb4, 0x3d, 0xdf, 0x00,
		0x9f, 0xfd, 0x13, 0xe1, 0x7b, 0xe3, 0x57, 0x38, 0xe4, 0x78, 0xcc, 0xa1, 0x17, 0x7b, 0x2a, 0x17,
		0x4f, 0x13, 0x97, 0x6e, 0x50, 0xda, 0x60, 0x87, 0x92, 0x32, 0xff, 0x12, 0xce, 0x40, 0xb3, 0x5f,
		0x14, 0x61, 0x55, 0x46, 0xcf, 0xa0, 0xb3, 0xb2, 0x1d, 0xec, 0xd1, 0x84, 0x07, 0x62, 0xe4, 0x4a,
	}

	// Parsed versions of the digests stored in the manifest above.
	blockDigests := []digest.Digest{
		digest.MustNewDigest(
			"instance",
			"B3Z:644b2abb353f636c4dd6c7a41eab8a281340b0c09b7c1af2f5ba0bc9d9724839",
			2048),
		digest.MustNewDigest(
			"instance",
			"B3Z:8e496dd725efb5d26caf4666428bbf848db12fcfd7e15a6489d3ce66dc86243c",
			2048),
		digest.MustNewDigest(
			"instance",
			"B3Z:7a8c6ae8da047e8901aba7f817db8bf95118e36781aee194d19a9aa5018ab55a",
			1025),
	}

	// Perform block lookups.
	blockDigest, offset := manifestParser.GetBlockDigest(manifest, 0)
	require.Equal(t, blockDigest, blockDigests[0])
	require.Equal(t, int64(0), offset)

	blockDigest, offset = manifestParser.GetBlockDigest(manifest, 2047)
	require.Equal(t, blockDigest, blockDigests[0])
	require.Equal(t, int64(0), offset)

	blockDigest, offset = manifestParser.GetBlockDigest(manifest, 2048)
	require.Equal(t, blockDigest, blockDigests[1])
	require.Equal(t, int64(2048), offset)

	blockDigest, offset = manifestParser.GetBlockDigest(manifest, 4095)
	require.Equal(t, blockDigest, blockDigests[1])
	require.Equal(t, int64(2048), offset)

	blockDigest, offset = manifestParser.GetBlockDigest(manifest, 4096)
	require.Equal(t, blockDigest, blockDigests[2])
	require.Equal(t, int64(4096), offset)

	blockDigest, offset = manifestParser.GetBlockDigest(manifest, 5120)
	require.Equal(t, blockDigest, blockDigests[2])
	require.Equal(t, int64(4096), offset)
}

func TestManifestParserAppendBlockDigest(t *testing.T) {
	// Construct a ManifestParser for an object consisting of three
	// blocks.
	blobDigest := digest.MustNewDigest(
		"instance",
		"B3Z:e8ff3078cf310f0cb86d073afb4e554a9cc63cf6af511fcdbfa287b4fe16b886",
		5121)
	manifestDigest, manifestParser, ok := blobDigest.ToManifest(2048)
	require.True(t, ok)
	require.Equal(
		t,
		digest.MustNewDigest(
			"instance",
			"B3ZM:e8ff3078cf310f0cb86d073afb4e554a9cc63cf6af511fcdbfa287b4fe16b886",
			192),
		manifestDigest)

	// The data that corresponds to the digest above.
	identity251 := make([]byte, 5121)
	for i := 0; i < len(identity251); i++ {
		identity251[i] = byte(i % 251)
	}

	// Append individual blocks to the manifest.
	manifest := make([]byte, 0, 192)
	require.Equal(
		t,
		digest.MustNewDigest(
			"instance",
			"B3Z:dfdc7b9119fcedb2a1b4a10e0893b6108e321d3eb48e41063fb7501be23574c4",
			2048),
		manifestParser.AppendBlockDigest(&manifest, identity251[:2048]))
	require.Equal(
		t,
		digest.MustNewDigest(
			"instance",
			"B3Z:f731c1fbe7ca27c2db3a07f8de137adc3085c2df2922d29dc030d33b61e1e8b7",
			2048),
		manifestParser.AppendBlockDigest(&manifest, identity251[2048:4096]))
	require.Equal(
		t,
		digest.MustNewDigest(
			"instance",
			"B3Z:7831f88cfa883af5c7c9d7f7c01e14897135b2854ca7b163beaca940bc79fdc3",
			1025),
		manifestParser.AppendBlockDigest(&manifest, identity251[4096:]))

	// Validate the resulting manifest.
	require.Equal(t, []byte{
		// First block.
		0x5c, 0x9e, 0x65, 0x44, 0x11, 0xe3, 0x93, 0xd1, 0xf4, 0xbe, 0xc7, 0x10, 0xcc, 0xd5, 0xbc, 0x56,
		0x69, 0xab, 0x17, 0x7d, 0x61, 0x0a, 0x0e, 0xb6, 0x91, 0xfc, 0xfe, 0xe9, 0x2f, 0xb4, 0xe8, 0xb1,
		0xd0, 0x98, 0xac, 0x7e, 0x5e, 0x0d, 0x84, 0xd2, 0xa8, 0x1d, 0x42, 0x99, 0x1c, 0x2f, 0x88, 0x1a,
		0xc3, 0x7d, 0xd8, 0x0b, 0xea, 0x3f, 0x22, 0x3d, 0xdf, 0x9e, 0x7c, 0x60, 0x31, 0x63, 0x06, 0xf6,
		// Second block.
		0x63, 0x91, 0xd0, 0x90, 0x21, 0xe4, 0x9b, 0xeb, 0x97, 0xa3, 0x66, 0x8d, 0x06, 0x16, 0xde, 0x09,
		0x98, 0xbe, 0x38, 0x82, 0x0b, 0x53, 0xaa, 0xb7, 0x58, 0x72, 0x26, 0x47, 0x13, 0x3a, 0xe0, 0xe3,
		0x04, 0xd6, 0xd1, 0x10, 0x51, 0x7a, 0xeb, 0xb2, 0x62, 0x01, 0x02, 0xf6, 0xea, 0x7c, 0xa1, 0x7c,
		0x0b, 0x40, 0x18, 0x3c, 0xb8, 0x37, 0x1c, 0x39, 0xf6, 0x0f, 0x2a, 0x57, 0x99, 0x00, 0xe5, 0x61,
		// Third block.
		0xa9, 0x9c, 0xd6, 0xca, 0xc0, 0xfd, 0x26, 0xee, 0x26, 0x49, 0xf4, 0xfc, 0xd6, 0x78, 0xdd, 0xc8,
		0x6f, 0x5c, 0x8b, 0xa8, 0x5e, 0x18, 0xd3, 0x08, 0x06, 0x39, 0xf0, 0xed, 0x76, 0x1a, 0xb1, 0xcd,
		0xb1, 0x89, 0x06, 0xbf, 0x21, 0x9b, 0x06, 0xca, 0xe5, 0x1d, 0x56, 0x6f, 0xb8, 0x97, 0x18, 0xc5,
		0x73, 0xda, 0x38, 0x7a, 0x3e, 0x31, 0xc1, 0xc2, 0x4f, 0x7d, 0x27, 0xd5, 0x5e, 0xe4, 0xf7, 0x49,
	}, manifest)
}
