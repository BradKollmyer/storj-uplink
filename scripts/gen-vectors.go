// Generate golden vectors for the native Rust uplink tests.
//
//	cd repo-root && go run ./scripts/gen-vectors.go
//
// Implements storj.io/common/encryption.DeriveRootKey and the path HMAC
// using the same primitives (HMAC-SHA256 mix, Argon2id, HMAC-SHA512 "path:").
// Also emits a synthetic Scope (grant_go.txt) with the same protobuf field
// tags as proto/scope.proto + encryption_access.proto (fields 1–3 only).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func deriveRootKey(password, salt, path []byte, threads uint8) []byte {
	mixed := hmacSHA256(password, salt)
	pathSalt := hmacSHA256(mixed, path)
	return argon2.IDKey(password, pathSalt, 1, 64*1024, threads, 32)
}

func pathComponent(key []byte, component string) []byte {
	h := hmac.New(sha512.New, key)
	h.Write([]byte("path:"))
	h.Write([]byte(component))
	sum := h.Sum(nil)
	return sum[:32]
}

func mustWrite(path, body string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", path)
}

func repoRoot() string {
	for _, c := range []string{".", ".."} {
		if _, err := os.Stat(filepath.Join(c, "crates/storj")); err == nil {
			return c
		}
	}
	panic("run from the storj-rust repo root or scripts/")
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func putVarint(buf *bytes.Buffer, n uint64) {
	for n >= 0x80 {
		buf.WriteByte(byte(n) | 0x80)
		n >>= 7
	}
	buf.WriteByte(byte(n))
}

func putBytes(buf *bytes.Buffer, field int, v []byte) {
	putVarint(buf, uint64(field<<3|2))
	putVarint(buf, uint64(len(v)))
	buf.Write(v)
}

func putString(buf *bytes.Buffer, field int, v string) {
	putBytes(buf, field, []byte(v))
}

func putVarintField(buf *bytes.Buffer, field int, v uint64) {
	putVarint(buf, uint64(field<<3))
	putVarint(buf, v)
}

// Bitcoin Base58Check matching storj.io/common/base58.CheckEncode.
const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func checksum4(in []byte) [4]byte {
	first := sha256.Sum256(in)
	second := sha256.Sum256(first[:])
	var out [4]byte
	copy(out[:], second[:4])
	return out
}

func base58Encode(input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	zero := big.NewInt(0)
	var out []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, b58Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func checkEncode(payload []byte, version byte) string {
	buf := make([]byte, 0, 1+len(payload)+4)
	buf = append(buf, version)
	buf = append(buf, payload...)
	sum := checksum4(buf)
	buf = append(buf, sum[:]...)
	return base58Encode(buf)
}

// Synthetic Scope: deterministic test macaroon + keys, not a production secret.
// Wire tags match proto/scope.proto and proto/encryption_access.proto (no field 4).
func encodeSyntheticGrant() string {
	const encAESGCM = 2

	store := new(bytes.Buffer)
	putBytes(store, 1, []byte("app"))
	putBytes(store, 2, []byte("user1"))
	putBytes(store, 3, []byte("enc-user1"))
	putBytes(store, 4, bytes.Repeat([]byte{0x44}, 32))
	putVarintField(store, 5, encAESGCM)

	enc := new(bytes.Buffer)
	putBytes(enc, 1, bytes.Repeat([]byte{0x33}, 32))
	putBytes(enc, 2, store.Bytes())
	putVarintField(enc, 3, encAESGCM)

	scope := new(bytes.Buffer)
	putString(scope, 1, "12edKaxTestSatelliteId@127.0.0.1:7777")
	putBytes(scope, 2, mustHex("020220111111111111111111111111111111111111111111111111111111111111111100000620f0926e6c10f7df4255267f188f709515131b530a341cde14415129209b7ef42a"))
	putBytes(scope, 3, enc.Bytes())

	return checkEncode(scope.Bytes(), 0)
}

func main() {
	if got := checkEncode([]byte("Hello World"), 0); got != "132UWxgjUJDXeRwy8XYYVQ" {
		panic("base58check mismatch vs storj.io/common/base58: " + got)
	}

	root := filepath.Join(repoRoot(), "crates/storj/tests/fixtures")

	pass := "correct horse battery staple"
	salt := []byte("0123456789abcdef")

	var deriveLines string
	for _, p := range []uint8{1, 8} {
		for _, path := range []string{"", "logs"} {
			key := deriveRootKey([]byte(pass), salt, []byte(path), p)
			deriveLines += fmt.Sprintf(
				`{"passphrase":%q,"salt_hex":%q,"path":%q,"parallelism":%d,"key_hex":%q}`+"\n",
				pass, hex.EncodeToString(salt), path, p, hex.EncodeToString(key),
			)
		}
	}
	mustWrite(filepath.Join(root, "derive_root_key.jsonl"), deriveLines)

	key := make([]byte, 32)
	for i := range key {
		key[i] = 7
	}
	var pathLines string
	for _, c := range []string{"", "logs", "café", "user1"} {
		out := pathComponent(key, c)
		pathLines += fmt.Sprintf(
			`{"key_hex":%q,"component":%q,"out_hex":%q}`+"\n",
			hex.EncodeToString(key), c, hex.EncodeToString(out),
		)
	}
	mustWrite(filepath.Join(root, "path_hmac.jsonl"), pathLines)

	mustWrite(filepath.Join(root, "grant_go.txt"), encodeSyntheticGrant()+"\n")

	fmt.Println("KDF + path HMAC + synthetic grant goldens ready.")
}
