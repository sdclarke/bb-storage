package blake3zcc

import (
	"math/bits"
)

// Constants and algorithms copied from the BLAKE3 specification.
// https://github.com/BLAKE3-team/BLAKE3-specs/raw/master/blake3.pdf

const (
	// Sizes of blocks and chunks that make up BLAKE3's Merkle tree.
	maximumBlockSize      = 64
	maximumBlocksPerChunk = 1024 / 64

	// Values for input d of the BLAKE3 compression function, as
	// specified in table 3 on page 6.
	flagChunkStart uint32 = 1 << 0
	flagChunkEnd   uint32 = 1 << 1
	flagParent     uint32 = 1 << 2
	flagRoot       uint32 = 1 << 3
)

// Initialization vectors, as specified in table 1 on page 5.
var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// The G function, as specified on page 5.
func g(a, b, c, d, m0, m1 uint32) (uint32, uint32, uint32, uint32) {
	a += b + m0
	d = bits.RotateLeft32(d^a, -16)
	c += d
	b = bits.RotateLeft32(b^c, -12)
	a += b + m1
	d = bits.RotateLeft32(d^a, -8)
	c += d
	b = bits.RotateLeft32(b^c, -7)
	return a, b, c, d
}

// The compression function, as specified on pages 4 to 6.
//
// TODO: Provide optimized versions that use AVX, SSE, etc.
func compress(h *[8]uint32, m *[16]uint32, t uint64, b uint32, d uint32) [16]uint32 {
	// Round 1.
	v0, v4, v8, v12 := g(h[0], h[4], iv[0], uint32(t), m[0], m[1])
	v1, v5, v9, v13 := g(h[1], h[5], iv[1], uint32(t)>>32, m[2], m[3])
	v2, v6, v10, v14 := g(h[2], h[6], iv[2], b, m[4], m[5])
	v3, v7, v11, v15 := g(h[3], h[7], iv[3], d, m[6], m[7])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[8], m[9])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[10], m[11])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[12], m[13])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[14], m[15])

	// Round 2.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[2], m[6])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[3], m[10])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[7], m[0])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[4], m[13])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[1], m[11])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[12], m[5])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[9], m[14])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[15], m[8])

	// Round 3.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[3], m[4])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[10], m[12])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[13], m[2])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[7], m[14])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[6], m[5])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[9], m[0])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[11], m[15])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[8], m[1])

	// Round 4.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[10], m[7])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[12], m[9])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[14], m[3])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[13], m[15])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[4], m[0])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[11], m[2])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[5], m[8])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[1], m[6])

	// Round 5.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[12], m[13])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[9], m[11])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[15], m[10])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[14], m[8])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[7], m[2])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[5], m[3])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[0], m[1])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[6], m[4])

	// Round 6.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[9], m[14])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[11], m[5])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[8], m[12])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[15], m[1])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[13], m[3])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[0], m[10])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[2], m[6])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[4], m[7])

	// Round 7.
	v0, v4, v8, v12 = g(v0, v4, v8, v12, m[11], m[15])
	v1, v5, v9, v13 = g(v1, v5, v9, v13, m[5], m[0])
	v2, v6, v10, v14 = g(v2, v6, v10, v14, m[1], m[9])
	v3, v7, v11, v15 = g(v3, v7, v11, v15, m[8], m[6])
	v0, v5, v10, v15 = g(v0, v5, v10, v15, m[14], m[10])
	v1, v6, v11, v12 = g(v1, v6, v11, v12, m[2], m[12])
	v2, v7, v8, v13 = g(v2, v7, v8, v13, m[3], m[4])
	v3, v4, v9, v14 = g(v3, v4, v9, v14, m[7], m[13])

	// Output of the compression function, as specified on page 6.
	return [...]uint32{
		v0 ^ v8, v1 ^ v9, v2 ^ v10, v3 ^ v11,
		v4 ^ v12, v5 ^ v13, v6 ^ v14, v7 ^ v15,
		v8 ^ h[0], v9 ^ h[1], v10 ^ h[2], v11 ^ h[3],
		v12 ^ h[4], v13 ^ h[5], v14 ^ h[6], v15 ^ h[7],
	}
}

// Truncate the output of the compression function to 256 bits to obtain
// a chaining value.
func truncate(in [16]uint32) (out [8]uint32) {
	copy(out[:], in[:])
	return
}

// Concatenate two chaining values to obtain a parent node message.
func concatenate(a *[8]uint32, b *[8]uint32) (out [16]uint32) {
	copy(out[:], (*a)[:])
	copy(out[8:], (*b)[:])
	return
}
