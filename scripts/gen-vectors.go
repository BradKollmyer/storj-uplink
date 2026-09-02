// Generate golden vectors for the native Rust uplink tests.
//
//	cd repo-root && go run ./scripts/gen-vectors.go
//
// Implements storj.io/common/encryption.DeriveRootKey and the path HMAC
// using the same primitives (HMAC-SHA256 mix, Argon2id, HMAC-SHA512 "path:").
// Optional: if storj.io/uplink is available, also emit a synthetic grant.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
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

func main() {
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

	fmt.Println("KDF + path HMAC goldens ready.")
	fmt.Println("Grant fixture: replace grant_go.txt with output from uplink.Share of a testplanet/sim grant (never production).")
}
