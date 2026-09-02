// (C) 1996-1998 Luigi Rizzo (luigi@iet.unipi.it)
//     2009-2010 Jack Lloyd (lloyd@randombit.net)
//     2011 Billy Brumley (billy.brumley@aalto.fi)
//     2016-2017 Vivint, Inc. (jeff.wendling@vivint.com)
//
// Portions derived from code by Phil Karn (karn@ka9q.ampr.org),
// Robert Morelos-Zaragoza (robert@spectra.eng.hawaii.edu) and Hari
// Thirumoorthy (harit@spectra.eng.hawaii.edu), Aug 1995
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Infectious-compatible Reed-Solomon (Rizzo/zfec systematic matrix).
//!
//! Port of `storj.io/infectious` `NewFEC` / `Encode` / `EncodeSingle` / `Rebuild`.
//! Decode is erasure-only (known missing shares). Piece hashes identify
//! corruption on the Uplink data path; Berlekamp-Welch is not required.

use crate::error::{Error, Result};
use crate::gf::{addmul, create_inverted_vdm, gf, invert_matrix};

/// Reed-Solomon codec: stripe of `k * share_size` → `n` shares of `share_size`.
///
/// Matches Go `eestream` / `infectious`. First `k` shares are the original
/// stripe (systematic). Any `k` of the `n` shares reconstruct the stripe.
#[derive(Clone)]
pub struct ReedSolomon {
    k: usize,
    n: usize,
    share_size: usize,
    /// `n * k` row-major encoding matrix (identity on the first `k` rows).
    enc_matrix: Vec<u8>,
}

impl std::fmt::Debug for ReedSolomon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReedSolomon")
            .field("k", &self.k)
            .field("n", &self.n)
            .field("share_size", &self.share_size)
            .finish_non_exhaustive()
    }
}

impl ReedSolomon {
    /// Build a codec. `1 <= k <= n <= 256`, `share_size > 0`.
    pub fn new(k: usize, n: usize, share_size: usize) -> Result<Self> {
        if k == 0 || share_size == 0 || n < k || n > 256 {
            return Err(Error::InvalidParams { k, n, share_size });
        }
        Ok(Self {
            k,
            n,
            share_size,
            enc_matrix: build_enc_matrix(k, n),
        })
    }

    /// Required shares (`k`).
    pub fn k(&self) -> usize {
        self.k
    }

    /// Total shares (`n`).
    pub fn n(&self) -> usize {
        self.n
    }

    /// Bytes per share.
    pub fn share_size(&self) -> usize {
        self.share_size
    }

    /// Stripe length: `k * share_size`.
    pub fn stripe_size(&self) -> usize {
        self.k * self.share_size
    }

    /// Encode a stripe into `n` owned shares.
    pub fn encode_stripe(&self, stripe: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut shares = vec![vec![0u8; self.share_size]; self.n];
        self.encode_stripe_into(stripe, &mut shares)?;
        Ok(shares)
    }

    /// Encode a stripe into caller-provided share buffers (length `n`).
    pub fn encode_stripe_into<S: AsMut<[u8]>>(
        &self,
        stripe: &[u8],
        shares: &mut [S],
    ) -> Result<()> {
        self.check_stripe(stripe)?;
        if shares.len() != self.n {
            return Err(Error::ShareCount {
                got: shares.len(),
                n: self.n,
            });
        }
        for (i, share) in shares.iter_mut().enumerate() {
            let out = share.as_mut();
            if out.len() != self.share_size {
                return Err(Error::ShareSize {
                    index: i,
                    got: out.len(),
                    want: self.share_size,
                });
            }
            self.encode_share_unchecked(stripe, i, out);
        }
        Ok(())
    }

    /// Encode a single share `index` (`0..n`) into `out` (`share_size` bytes).
    pub fn encode_share(&self, stripe: &[u8], index: usize, out: &mut [u8]) -> Result<()> {
        self.check_stripe(stripe)?;
        if index >= self.n {
            return Err(Error::InvalidShareIndex { index, n: self.n });
        }
        if out.len() != self.share_size {
            return Err(Error::ShareSize {
                index,
                got: out.len(),
                want: self.share_size,
            });
        }
        self.encode_share_unchecked(stripe, index, out);
        Ok(())
    }

    /// Reconstruct a stripe from `n` slots; missing shares are `None`.
    ///
    /// Any `k` present shares are enough. Extra shares are unused (erasures,
    /// not Berlekamp-Welch).
    pub fn decode_stripe(&self, shares: &[Option<&[u8]>]) -> Result<Vec<u8>> {
        if shares.len() != self.n {
            return Err(Error::ShareCount {
                got: shares.len(),
                n: self.n,
            });
        }
        let mut present = Vec::with_capacity(self.k);
        for (i, s) in shares.iter().enumerate() {
            if let Some(data) = *s {
                if data.len() != self.share_size {
                    return Err(Error::ShareSize {
                        index: i,
                        got: data.len(),
                        want: self.share_size,
                    });
                }
                present.push((i, data));
            }
        }
        self.decode_from(&present)
    }

    /// Reconstruct from indexed shares. At least `k` unique indexes in `0..n`.
    pub fn decode_from(&self, shares: &[(usize, &[u8])]) -> Result<Vec<u8>> {
        if shares.len() < self.k {
            return Err(Error::TooFewShares {
                have: shares.len(),
                need: self.k,
            });
        }
        let mut ordered: Vec<(usize, &[u8])> = Vec::with_capacity(shares.len());
        for &(index, data) in shares {
            if index >= self.n {
                return Err(Error::InvalidShareIndex { index, n: self.n });
            }
            if data.len() != self.share_size {
                return Err(Error::ShareSize {
                    index,
                    got: data.len(),
                    want: self.share_size,
                });
            }
            ordered.push((index, data));
        }
        ordered.sort_unstable_by_key(|(i, _)| *i);
        for w in ordered.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(Error::DuplicateShare { index: w[0].0 });
            }
        }
        self.rebuild(&ordered)
    }

    fn check_stripe(&self, stripe: &[u8]) -> Result<()> {
        let want = self.stripe_size();
        if stripe.len() != want {
            return Err(Error::StripeSize {
                got: stripe.len(),
                want,
            });
        }
        Ok(())
    }

    fn encode_share_unchecked(&self, stripe: &[u8], index: usize, out: &mut [u8]) {
        let ss = self.share_size;
        if index < self.k {
            out.copy_from_slice(&stripe[index * ss..(index + 1) * ss]);
            return;
        }
        out.fill(0);
        for j in 0..self.k {
            addmul(
                out,
                &stripe[j * ss..(j + 1) * ss],
                self.enc_matrix[index * self.k + j],
            );
        }
    }

    /// Infectious `Rebuild`: prefer data shares, fill holes from high indexes.
    fn rebuild(&self, shares: &[(usize, &[u8])]) -> Result<Vec<u8>> {
        let k = self.k;
        let ss = self.share_size;
        let mut m_dec = vec![0u8; k * k];
        let mut indexes = vec![0usize; k];
        let mut sharesv: Vec<&[u8]> = vec![&[]; k];

        let mut b = 0usize;
        let mut e = shares.len();
        for i in 0..k {
            let (share_id, share_data) = if b < e && shares[b].0 == i {
                let s = shares[b];
                b += 1;
                s
            } else {
                e -= 1;
                shares[e]
            };
            if share_id < k {
                m_dec[i * (k + 1)] = 1;
            } else {
                m_dec[i * k..i * k + k]
                    .copy_from_slice(&self.enc_matrix[share_id * k..share_id * k + k]);
            }
            sharesv[i] = share_data;
            indexes[i] = share_id;
        }

        invert_matrix(&mut m_dec, k).map_err(Error::Reconstruct)?;

        let mut stripe = vec![0u8; self.stripe_size()];
        for i in 0..k {
            if indexes[i] < k {
                let dest = indexes[i];
                stripe[dest * ss..(dest + 1) * ss].copy_from_slice(sharesv[i]);
            } else {
                let dest = &mut stripe[i * ss..(i + 1) * ss];
                dest.fill(0);
                for col in 0..k {
                    addmul(dest, sharesv[col], m_dec[i * k + col]);
                }
            }
        }
        Ok(stripe)
    }
}

fn build_enc_matrix(k: usize, n: usize) -> Vec<u8> {
    let gf = gf();
    let mut enc_matrix = vec![0u8; n * k];
    let mut temp_matrix = vec![0u8; n * k];
    create_inverted_vdm(&mut temp_matrix, k);
    for (i, slot) in temp_matrix.iter_mut().enumerate().skip(k * k) {
        *slot = gf.exp[((i / k) * (i % k)) % 255];
    }
    for i in 0..k {
        enc_matrix[i * (k + 1)] = 1;
    }
    let mut row = k * k;
    while row < n * k {
        for col in 0..k {
            let mut acc = 0u8;
            for i in 0..k {
                acc ^= gf.mul[temp_matrix[row + i] as usize][temp_matrix[col + i * k] as usize];
            }
            enc_matrix[row + col] = acc;
        }
        row += k;
    }
    enc_matrix
}
