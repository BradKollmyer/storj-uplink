//! Reed-Solomon erasure coding for Storj stripes.
//!
//! Implementation detail of the `storj` crate; not a stable public API.
//! Depend on `storj` instead.
//!
//! Shipping codec matches Go `storj.io/infectious` / `eestream` byte-for-byte
//! (Rizzo/zfec systematic matrix over GF(2^8), poly 0x11d).
//!
//! `reed-solomon-erasure` (Klaus Post / Backblaze Vandermonde) is a workspace
//! pin compared in tests (K16). It shares the field polynomial but **not** the
//! encoding matrix, so its parity shares diverge.

#![deny(clippy::undocumented_unsafe_blocks)]

mod error;
mod fec;
mod gf;
mod gf_simd;

pub use error::{Error, Result};
pub use fec::{DecodePlan, ReedSolomon};

/// Encode a stripe (`k * share_size` bytes) into `n` shares.
pub fn encode_stripe(k: usize, n: usize, share_size: usize, stripe: &[u8]) -> Result<Vec<Vec<u8>>> {
    ReedSolomon::new(k, n, share_size)?.encode_stripe(stripe)
}

/// Decode a stripe from any `k` of `n` indexed shares.
pub fn decode_stripe(
    k: usize,
    n: usize,
    share_size: usize,
    shares: &[Option<&[u8]>],
) -> Result<Vec<u8>> {
    ReedSolomon::new(k, n, share_size)?.decode_stripe(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill_stripe(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8) ^ ((i >> 8) as u8) ^ 0xa5)
            .collect()
    }

    fn drop_to_options<'a>(shares: &'a [Vec<u8>], drop: &[usize]) -> Vec<Option<&'a [u8]>> {
        shares
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if drop.contains(&i) {
                    None
                } else {
                    Some(s.as_slice())
                }
            })
            .collect()
    }

    #[test]
    fn round_trip_small() {
        let k = 4;
        let n = 6;
        let ss = 8;
        let stripe = fill_stripe(k * ss);
        let rs = ReedSolomon::new(k, n, ss).unwrap();
        let shares = rs.encode_stripe(&stripe).unwrap();
        assert_eq!(shares.len(), n);
        assert_eq!(&shares[0], &stripe[..ss]);
        let got = rs.decode_stripe(&drop_to_options(&shares, &[])).unwrap();
        assert_eq!(got, stripe);
    }

    #[test]
    fn drop_n_minus_k_still_decodes() {
        let k = 4;
        let n = 6;
        let ss = 8;
        let stripe = fill_stripe(k * ss);
        let rs = ReedSolomon::new(k, n, ss).unwrap();
        let shares = rs.encode_stripe(&stripe).unwrap();
        // Drop two data shares; reconstruct from remaining k.
        let got = rs
            .decode_stripe(&drop_to_options(&shares, &[0, 1]))
            .unwrap();
        assert_eq!(got, stripe);
        let got = rs
            .decode_stripe(&drop_to_options(&shares, &[4, 5]))
            .unwrap();
        assert_eq!(got, stripe);
        let got = rs
            .decode_stripe(&drop_to_options(&shares, &[1, 5]))
            .unwrap();
        assert_eq!(got, stripe);
    }

    #[test]
    fn k_minus_one_fails() {
        let k = 4;
        let n = 6;
        let ss = 8;
        let stripe = fill_stripe(k * ss);
        let rs = ReedSolomon::new(k, n, ss).unwrap();
        let shares = rs.encode_stripe(&stripe).unwrap();
        let err = rs
            .decode_stripe(&drop_to_options(&shares, &[0, 1, 2]))
            .unwrap_err();
        assert_eq!(
            err,
            Error::TooFewShares {
                have: k - 1,
                need: k
            }
        );
    }

    #[test]
    fn k_equals_n_is_copy() {
        let rs = ReedSolomon::new(3, 3, 4).unwrap();
        let stripe = fill_stripe(12);
        let shares = rs.encode_stripe(&stripe).unwrap();
        assert_eq!(shares.concat(), stripe);
        assert_eq!(
            rs.decode_from(&[(0, &shares[0]), (1, &shares[1]), (2, &shares[2])])
                .unwrap(),
            stripe
        );
    }

    #[test]
    fn encode_share_matches_full_encode() {
        let rs = ReedSolomon::new(4, 6, 8).unwrap();
        let stripe = fill_stripe(32);
        let all = rs.encode_stripe(&stripe).unwrap();
        for (i, expected) in all.iter().enumerate() {
            let mut out = vec![0u8; 8];
            rs.encode_share(&stripe, i, &mut out).unwrap();
            assert_eq!(&out, expected);
        }
    }

    #[test]
    fn rejects_bad_params() {
        assert!(ReedSolomon::new(0, 1, 1).is_err());
        assert!(ReedSolomon::new(2, 1, 1).is_err());
        assert!(ReedSolomon::new(1, 257, 1).is_err());
        assert!(ReedSolomon::new(1, 1, 0).is_err());
    }

    #[test]
    fn duplicate_share_fails() {
        let rs = ReedSolomon::new(2, 4, 2).unwrap();
        let stripe = fill_stripe(4);
        let shares = rs.encode_stripe(&stripe).unwrap();
        let err = rs
            .decode_from(&[(0, shares[0].as_slice()), (0, shares[0].as_slice())])
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateShare { index: 0 }));
    }

    #[test]
    fn test_scheme_round_trip() {
        // Satellite releaseDefault 29/35/80/110-256B (tests only).
        const K: usize = 29;
        const N: usize = 110;
        const SS: usize = 256;
        let stripe = fill_stripe(K * SS);
        let rs = ReedSolomon::new(K, N, SS).unwrap();
        assert_eq!(rs.stripe_size(), 7424);
        let shares = rs.encode_stripe(&stripe).unwrap();
        // Drop n-k = 81 shares (keep first k).
        let mut slots: Vec<Option<&[u8]>> = vec![None; N];
        for (i, s) in shares.iter().take(K).enumerate() {
            slots[i] = Some(s.as_slice());
        }
        assert_eq!(rs.decode_stripe(&slots).unwrap(), stripe);
        // Keep last k (all parity except we need mix: last k of n).
        slots.fill(None);
        for (slot, share) in slots.iter_mut().skip(N - K).zip(shares.iter().skip(N - K)) {
            *slot = Some(share.as_slice());
        }
        assert_eq!(rs.decode_stripe(&slots).unwrap(), stripe);
    }

    /// LCG fuzz: random stripes, random erasures, never panics, always round-trips.
    #[test]
    fn fuzz_random_erasures() {
        let mut state = 0xec41_u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as u8
        };
        for (k, n, ss, iters) in [(3, 5, 16, 64), (8, 14, 2, 32), (29, 110, 256, 8)] {
            let rs = ReedSolomon::new(k, n, ss).unwrap();
            for _ in 0..iters {
                let stripe: Vec<u8> = (0..k * ss).map(|_| next()).collect();
                let shares = rs.encode_stripe(&stripe).unwrap();
                let mut drop = vec![false; n];
                let mut dropped = 0;
                while dropped < n - k {
                    let i = next() as usize % n;
                    if !drop[i] {
                        drop[i] = true;
                        dropped += 1;
                    }
                }
                let slots: Vec<Option<&[u8]>> = shares
                    .iter()
                    .enumerate()
                    .map(|(i, s)| if drop[i] { None } else { Some(s.as_slice()) })
                    .collect();
                assert_eq!(rs.decode_stripe(&slots).unwrap(), stripe);
            }
        }
    }

    /// `reed-solomon-erasure` shares the GF poly but not the Rizzo matrix.
    /// Pin the divergence so we do not silently ship Klaus Post parity.
    #[test]
    fn reed_solomon_erasure_diverges_from_infectious() {
        const K: usize = 4;
        const N: usize = 6;
        const SS: usize = 8;
        let stripe = fill_stripe(K * SS);
        let infectious = ReedSolomon::new(K, N, SS)
            .unwrap()
            .encode_stripe(&stripe)
            .unwrap();

        let rse = reed_solomon_erasure::galois_8::ReedSolomon::new(K, N - K).unwrap();
        let mut rse_shards: Vec<Vec<u8>> = (0..K)
            .map(|i| stripe[i * SS..(i + 1) * SS].to_vec())
            .chain((0..(N - K)).map(|_| vec![0u8; SS]))
            .collect();
        rse.encode(&mut rse_shards).unwrap();

        assert_eq!(
            &infectious[..K],
            &rse_shards[..K],
            "both are systematic: data shares must match"
        );
        assert_ne!(
            infectious[K], rse_shards[K],
            "reed-solomon-erasure parity matched infectious; the Rizzo port can be dropped"
        );
    }
}
