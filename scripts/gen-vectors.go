// Generate golden vectors for the native Rust uplink tests.
//
//	go run -C scripts .
//
// Calls storj.io/common encryption.DeriveRootKey, encryption.DeriveKey, and
// grant.Serialize / ParseAccess so fixtures track the pinned Go implementation.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/macaroon"
	"storj.io/common/paths"
	"storj.io/common/storj"
)

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
	panic("run from the storj-rust repo root or scripts/ via go run -C scripts .")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func mustErr(err error) {
	if err != nil {
		panic(err)
	}
}

func keyByte(b byte) storj.Key {
	var k storj.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// Synthetic grant: deterministic test macaroon + keys, not a production secret.
func encodeSyntheticGrant() string {
	apiKey := must(macaroon.FromParts(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0xaa}, 32)))

	defaultKey := keyByte(0x33)
	enc := grant.NewEncryptionAccessWithDefaultKey(&defaultKey)
	enc.SetDefaultPathCipher(storj.EncAESGCM)
	mustErr(enc.Store.AddWithCipher(
		"app",
		paths.NewUnencrypted("user1"),
		paths.NewEncrypted("enc-user1"),
		keyByte(0x44),
		storj.EncAESGCM,
	))

	access := &grant.Access{
		SatelliteAddress: "12edKaxTestSatelliteId@127.0.0.1:7777",
		APIKey:           apiKey,
		EncAccess:        enc,
	}
	serialized := must(access.Serialize())
	parsed := must(grant.ParseAccess(serialized))
	round := must(parsed.Serialize())
	if round != serialized {
		panic("grant.ParseAccess/Serialize is not identity")
	}
	return serialized
}

func main() {
	root := filepath.Join(repoRoot(), "crates/storj/tests/fixtures")

	pass := "correct horse battery staple"
	salt := []byte("0123456789abcdef")

	var deriveLines string
	for _, p := range []uint8{1, 8} {
		for _, path := range []string{"", "logs"} {
			key := must(encryption.DeriveRootKey([]byte(pass), salt, path, p))
			deriveLines += fmt.Sprintf(
				`{"passphrase":%q,"salt_hex":%q,"path":%q,"parallelism":%d,"key_hex":%q}`+"\n",
				pass, hex.EncodeToString(salt), path, p, hex.EncodeToString(key[:]),
			)
		}
	}
	mustWrite(filepath.Join(root, "derive_root_key.jsonl"), deriveLines)

	key := keyByte(7)
	var pathLines string
	for _, c := range []string{"", "logs", "café", "user1"} {
		out := must(encryption.DeriveKey(&key, "path:"+c))
		pathLines += fmt.Sprintf(
			`{"key_hex":%q,"component":%q,"out_hex":%q}`+"\n",
			hex.EncodeToString(key[:]), c, hex.EncodeToString(out[:]),
		)
	}
	mustWrite(filepath.Join(root, "path_hmac.jsonl"), pathLines)

	mustWrite(filepath.Join(root, "grant_go.txt"), encodeSyntheticGrant()+"\n")

	fmt.Println("KDF + path HMAC + synthetic grant goldens ready.")
}
