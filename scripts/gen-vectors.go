// Generate golden vectors for the native Rust uplink tests.
//
//	cd repo-root && go run ./scripts/gen-vectors.go
//
// Implements storj.io/common/encryption.DeriveRootKey and the path HMAC
// using the same primitives (HMAC-SHA256 mix, Argon2id, HMAC-SHA512 "path:").
// Also emits infectious Reed-Solomon goldens (`rs_shares.jsonl`, `rs_stripe.bin`).
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
	"strings"

	"golang.org/x/crypto/argon2"
	"storj.io/infectious"
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

	writeRSGoldens(root)

	fmt.Println("KDF + path HMAC goldens ready.")
	fmt.Println("Grant fixture: replace grant_go.txt with output from uplink.Share of a testplanet/sim grant (never production).")
}

func fillStripe(n int) []byte {
	stripe := make([]byte, n)
	for i := range stripe {
		stripe[i] = byte(i) ^ byte(i>>8) ^ 0xA5
	}
	return stripe
}

func rsRecord(k, n, shareSize int, stripe []byte) string {
	if len(stripe) != k*shareSize {
		panic(fmt.Sprintf("stripe len %d != k*share_size %d", len(stripe), k*shareSize))
	}
	f, err := infectious.NewFEC(k, n)
	if err != nil {
		panic(err)
	}
	shares := make([][]byte, n)
	err = f.Encode(stripe, func(s infectious.Share) {
		shares[s.Number] = append([]byte(nil), s.Data...)
	})
	if err != nil {
		panic(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"k":%d,"n":%d,"share_size":%d,"stripe_hex":"%s","shares_hex":[`,
		k, n, shareSize, hex.EncodeToString(stripe))
	for i, s := range shares {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%s"`, hex.EncodeToString(s))
	}
	b.WriteString("]}\n")
	return b.String()
}

func writeRSGoldens(root string) {
	// Small scheme: easy to inspect. Infectious README shape (k=8,n=14) plus 4/6.
	small := fillStripe(4 * 8)
	hello := []byte("hello, world! __") // k=8, share_size=2
	prod := fillStripe(29 * 256)

	var lines string
	lines += rsRecord(4, 6, 8, small)
	lines += rsRecord(8, 14, 2, hello)
	lines += rsRecord(29, 110, 256, prod)
	mustWrite(filepath.Join(root, "rs_shares.jsonl"), lines)
	mustWrite(filepath.Join(root, "rs_stripe.bin"), string(prod))
	fmt.Println("infectious RS goldens ready.")
}
