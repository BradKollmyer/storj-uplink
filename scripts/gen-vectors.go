// Generate golden vectors for the native Rust uplink tests.
//
//	go run -C scripts .
//
// Calls storj.io/common encryption.DeriveRootKey, encryption.DeriveKey, and
// grant.Serialize / ParseAccess so fixtures track the pinned Go implementation.
// Also emits infectious Reed-Solomon goldens (`rs_shares.jsonl`, `rs_stripe.bin`).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"storj.io/common/encryption"
	"storj.io/common/grant"
	"storj.io/common/identity"
	"storj.io/common/macaroon"
	"storj.io/common/paths"
	"storj.io/common/pb"
	"storj.io/common/signing"
	"storj.io/common/storj"
	"storj.io/infectious"
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
	panic("run from the storj-uplink repo root or scripts/ via go run -C scripts .")
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
	writeSignedGoldens(root)
	writeRSGoldens(root)

	fmt.Println("KDF + path HMAC + infectious RS + synthetic grant goldens ready.")
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

// writeSignedGoldens emits an OrderLimit signed by a satellite identity, a
// PieceHash signed by a storage-node identity, and an Order / PieceHash signed
// by an uplink piece key, all produced by storj.io/common/signing, together
// with the leaf and CA certificates. The Rust side must verify them with the
// *leaf* certificate (Go SigneeFromPeerIdentity) and must reject the CA.
//
// Identities are random, so the file is generated once and kept; delete it to
// regenerate.
func writeSignedGoldens(root string) {
	path := filepath.Join(root, "signed_go.jsonl")
	if _, err := os.Stat(path); err == nil {
		fmt.Println("keep", path, "(random identities; delete to regenerate)")
		return
	}
	ctx := context.Background()
	opts := identity.NewCAOptions{Difficulty: 0, Concurrency: 1}
	sat := must(identity.NewFullIdentity(ctx, opts))
	node := must(identity.NewFullIdentity(ctx, opts))
	pub, priv, err := storj.NewPieceKey()
	mustErr(err)

	created := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	var serial storj.SerialNumber
	copy(serial[:], bytes.Repeat([]byte{0x11}, len(serial)))
	var pieceID storj.PieceID
	copy(pieceID[:], bytes.Repeat([]byte{0x22}, len(pieceID)))

	limit := must(signing.SignOrderLimit(ctx, signing.SignerFromFullIdentity(sat), &pb.OrderLimit{
		SerialNumber:    serial,
		SatelliteId:     sat.ID,
		UplinkPublicKey: pub,
		StorageNodeId:   node.ID,
		PieceId:         pieceID,
		Limit:           4096,
		Action:          pb.PieceAction_PUT,
		PieceExpiration: created.Add(24 * time.Hour),
		OrderExpiration: created.Add(time.Hour),
		OrderCreation:   created,
	}))
	unsignedHash := &pb.PieceHash{
		PieceId:       pieceID,
		Hash:          bytes.Repeat([]byte{0x33}, 32),
		PieceSize:     4096,
		Timestamp:     created,
		HashAlgorithm: pb.PieceHashAlgorithm_SHA256,
	}
	// A production-shaped limit: encrypted metadata set, zero piece
	// expiration, deprecated satellite address present. Also emit the exact
	// bytes Go signs (EncodeOrderLimit) so the Rust encoder can be diffed.
	fullLimit := must(signing.SignOrderLimit(ctx, signing.SignerFromFullIdentity(sat), &pb.OrderLimit{
		SerialNumber:               serial,
		SatelliteId:                sat.ID,
		UplinkPublicKey:            pub,
		StorageNodeId:              node.ID,
		PieceId:                    pieceID,
		Limit:                      7424 * 3,
		Action:                     pb.PieceAction_GET,
		OrderExpiration:            created.Add(2 * time.Hour),
		OrderCreation:              created,
		EncryptedMetadataKeyId:     bytes.Repeat([]byte{0x44}, 16),
		EncryptedMetadata:          bytes.Repeat([]byte{0x55}, 48),
		DeprecatedSatelliteAddress: &pb.NodeAddress{Address: "sat.example:7777"},
	}))
	fullSigningBytes := must(signing.EncodeOrderLimit(ctx, fullLimit))
	nodeHash := must(signing.SignPieceHash(ctx, signing.SignerFromFullIdentity(node), unsignedHash))
	uplinkHash := must(signing.SignUplinkPieceHash(ctx, priv, unsignedHash))
	order := must(signing.SignUplinkOrder(ctx, priv, &pb.Order{SerialNumber: serial, Amount: 4096}))

	line := fmt.Sprintf(`{"satellite_leaf_der":"%x","satellite_ca_der":"%x","satellite_node_id":%q,`+
		`"node_leaf_der":"%x","node_ca_der":"%x","node_node_id":%q,"piece_public_key":"%x",`+
		`"order_limit":"%x","piece_hash_node":"%x","order_uplink":"%x","piece_hash_uplink":"%x",`+
		`"order_limit_full":"%x","order_limit_full_signing_bytes":"%x"}`+"\n",
		sat.Leaf.Raw, sat.CA.Raw, sat.ID.String(),
		node.Leaf.Raw, node.CA.Raw, node.ID.String(), pub.Bytes(),
		must(pb.Marshal(limit)), must(pb.Marshal(nodeHash)), must(pb.Marshal(order)), must(pb.Marshal(uplinkHash)),
		must(pb.Marshal(fullLimit)), fullSigningBytes)
	mustWrite(path, line)
}
