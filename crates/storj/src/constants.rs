//! Protocol constants copied from uplink-go / satellite config (cited in the design).
//! Production Reed-Solomon k/m/o/n is **not** hardcoded; BeginSegment supplies it.

/// Maximum plaintext+encrypted segment size. Satellite `MaxSegmentSize` default.
pub const MAX_SEGMENT_SIZE: u64 = 64 * 1024 * 1024;

/// Encrypted segments at or below this size are stored inline on the satellite.
pub const MAX_INLINE_SEGMENT_SIZE: u64 = 4 * 1024;

/// AES-GCM block size after the GCM tag. Uplink hardcodes `29 * 256 = 7424`.
/// Follow the **code**, not the “twice the stripe” comment.
pub const ENCRYPTION_BLOCK_SIZE: usize = 29 * 256;

/// Default RS share size in bytes (`releaseDefault` `…-256B`).
pub const DEFAULT_SHARE_SIZE: usize = 256;

/// Satellite `releaseDefault` RS scheme `29/35/80/110-256B` — **tests only**.
/// Production clients must use the scheme from `BeginSegment`.
pub const TEST_RS_K: usize = 29;
/// Optimal threshold.
pub const TEST_RS_M: usize = 35;
/// Pieces kept after long-tail.
pub const TEST_RS_O: usize = 80;
/// Pieces attempted.
pub const TEST_RS_N: usize = 110;

/// Argon2id time parameter (both `request_with_passphrase` and `EncryptionKey::derive`).
pub const ARGON2_TIME: u32 = 1;
/// Argon2id memory in KiB (64 MiB).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id output length.
pub const ARGON2_OUTPUT_LEN: usize = 32;
/// Parallelism for `Access::request_with_passphrase` (Go `access.go` hardcodes 8).
pub const ARGON2_PARALLELISM_REQUEST: u32 = 8;
/// Parallelism for `EncryptionKey::derive` (Go `DeriveEncryptionKey`).
pub const ARGON2_PARALLELISM_DERIVE: u32 = 1;

/// Default satellite dial timeout when `Config::dial_timeout` is `None` or zero.
pub const DEFAULT_DIAL_TIMEOUT_SECS: u64 = 20;

/// Multipart: minimum part size except the last (satellite config).
pub const MIN_MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;
/// Multipart: maximum number of parts.
pub const MAX_MULTIPART_PARTS: u32 = 10_000;

/// Access grant Base58Check version byte. `ParseAccess` rejects any other.
pub const GRANT_BASE58_VERSION: u8 = 0;

/// Macaroon binary version.
pub const MACAROON_VERSION: u8 = 2;

/// CompressedBatch zstd decoder memory cap (Go `WithDecoderMaxMemory(64<<20)`).
pub const COMPRESSED_BATCH_MAX_DECODE: usize = 64 * 1024 * 1024;

/// DRPC TLS mux prefix (`DRPC!!!1`).
pub const DRPC_TLS_MUX_PREFIX: &[u8] = b"DRPC!!!1";
/// DRPC Noise mux prefix (`DRPC!N!1`).
pub const DRPC_NOISE_MUX_PREFIX: &[u8] = b"DRPC!N!1";

/// HMAC info prefix for path component derivation.
pub const PATH_HMAC_PREFIX: &[u8] = b"path:";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_size_is_one_stripe_not_twice() {
        assert_eq!(ENCRYPTION_BLOCK_SIZE, 7424);
        assert_eq!(ENCRYPTION_BLOCK_SIZE, TEST_RS_K * DEFAULT_SHARE_SIZE);
        // The comment in Go says “twice the stripe”; the code is one stripe.
        assert_ne!(ENCRYPTION_BLOCK_SIZE, 2 * TEST_RS_K * DEFAULT_SHARE_SIZE);
    }

    #[test]
    fn argon2_parallelism_is_not_cpu_count() {
        assert_eq!(ARGON2_PARALLELISM_REQUEST, 8);
        assert_eq!(ARGON2_PARALLELISM_DERIVE, 1);
        assert_ne!(
            ARGON2_PARALLELISM_REQUEST, ARGON2_PARALLELISM_DERIVE,
            "request and derive must use different p; mixing them breaks grant interop"
        );
    }

    #[test]
    fn segment_and_inline_defaults() {
        assert_eq!(MAX_SEGMENT_SIZE, 64 * 1024 * 1024);
        assert_eq!(MAX_INLINE_SEGMENT_SIZE, 4096);
        const { assert!(MAX_INLINE_SEGMENT_SIZE < MAX_SEGMENT_SIZE) };
    }

    #[test]
    fn multipart_limits() {
        assert_eq!(MIN_MULTIPART_PART_SIZE, 5 * 1024 * 1024);
        assert_eq!(MAX_MULTIPART_PARTS, 10_000);
    }

    #[test]
    fn mux_prefixes() {
        assert_eq!(DRPC_TLS_MUX_PREFIX, b"DRPC!!!1");
        assert_eq!(DRPC_NOISE_MUX_PREFIX, b"DRPC!N!1");
    }
}
