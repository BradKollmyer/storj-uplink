//! SIMD `addmul` (`z[i] ^= y * x[i]` over GF(2^8)) using split-nibble tables:
//! multiplication by a constant is linear over GF(2), so
//! `y * x == T_lo[x & 0x0f] ^ T_hi[x >> 4]` with two 16-entry tables, which
//! map directly onto a 16-lane byte shuffle (`vqtbl1q_u8` / `pshufb`).
//! This is the classic Plank / Klaus Post approach infectious ships as
//! assembly for amd64. The scalar loop handles tails and hosts without the
//! feature.
#![deny(unsafe_op_in_unsafe_fn)]

use crate::gf::gf;

/// Build the low/high nibble tables for multiplication by `y`.
#[inline]
fn nibble_tables(y: u8) -> ([u8; 16], [u8; 16]) {
    let mul_y = &gf().mul[y as usize];
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    for i in 0..16 {
        lo[i] = mul_y[i];
        hi[i] = mul_y[i << 4];
    }
    (lo, hi)
}

/// Scalar reference / tail loop.
#[inline]
pub(crate) fn addmul_scalar(z: &mut [u8], x: &[u8], y: u8) {
    let mul_y = &gf().mul[y as usize];
    for (zi, &xi) in z.iter_mut().zip(x.iter()) {
        *zi ^= mul_y[xi as usize];
    }
}

/// `z[i] ^= y * x[i]` for `i < z.len()`; `x.len() >= z.len()`.
#[inline]
pub(crate) fn addmul(z: &mut [u8], x: &[u8], y: u8) {
    if y == 0 || z.is_empty() {
        return;
    }
    let n = z.len();
    let x = &x[..n];
    #[cfg(target_arch = "aarch64")]
    {
        // NEON is part of the aarch64 baseline; no runtime detection needed.
        // SAFETY: `x.len() == z.len()` (sliced above) and the function only
        // touches indexes below that length.
        unsafe { addmul_neon(z, x, y) };
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 verified at runtime; `x.len() == z.len()`.
            unsafe { addmul_ssse3(z, x, y) };
            return;
        }
    }
    #[allow(unreachable_code)]
    addmul_scalar(z, x, y);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn addmul_neon(z: &mut [u8], x: &[u8], y: u8) {
    use std::arch::aarch64::{
        vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8, vst1q_u8,
    };
    debug_assert_eq!(x.len(), z.len());
    let (lo, hi) = nibble_tables(y);
    let n = z.len();
    let chunks = n / 16;
    // SAFETY: table arrays are exactly 16 bytes; every load/store below is
    // within `0..chunks * 16 <= n` of slices whose lengths are both `n`.
    unsafe {
        let t_lo = vld1q_u8(lo.as_ptr());
        let t_hi = vld1q_u8(hi.as_ptr());
        let mask = vdupq_n_u8(0x0f);
        let xp = x.as_ptr();
        let zp = z.as_mut_ptr();
        for c in 0..chunks {
            let off = c * 16;
            let xv = vld1q_u8(xp.add(off));
            let zv = vld1q_u8(zp.add(off));
            let l = vqtbl1q_u8(t_lo, vandq_u8(xv, mask));
            let h = vqtbl1q_u8(t_hi, vshrq_n_u8::<4>(xv));
            vst1q_u8(zp.add(off), veorq_u8(zv, veorq_u8(l, h)));
        }
    }
    let done = chunks * 16;
    addmul_scalar(&mut z[done..], &x[done..], y);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn addmul_ssse3(z: &mut [u8], x: &[u8], y: u8) {
    use std::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_loadu_si128, _mm_set1_epi8, _mm_shuffle_epi8, _mm_srli_epi16,
        _mm_storeu_si128, _mm_xor_si128,
    };
    debug_assert_eq!(x.len(), z.len());
    let (lo, hi) = nibble_tables(y);
    let n = z.len();
    let chunks = n / 16;
    // SAFETY: unaligned loads/stores of 16 bytes at offsets below
    // `chunks * 16 <= n` of slices whose lengths are both `n`; the tables are
    // exactly 16 bytes.
    unsafe {
        let t_lo = _mm_loadu_si128(lo.as_ptr().cast::<__m128i>());
        let t_hi = _mm_loadu_si128(hi.as_ptr().cast::<__m128i>());
        let mask = _mm_set1_epi8(0x0f);
        let xp = x.as_ptr();
        let zp = z.as_mut_ptr();
        for c in 0..chunks {
            let off = c * 16;
            let xv = _mm_loadu_si128(xp.add(off).cast::<__m128i>());
            let zv = _mm_loadu_si128(zp.add(off).cast::<__m128i>());
            let l = _mm_shuffle_epi8(t_lo, _mm_and_si128(xv, mask));
            let h = _mm_shuffle_epi8(t_hi, _mm_and_si128(_mm_srli_epi16::<4>(xv), mask));
            _mm_storeu_si128(
                zp.add(off).cast::<__m128i>(),
                _mm_xor_si128(zv, _mm_xor_si128(l, h)),
            );
        }
    }
    let done = chunks * 16;
    addmul_scalar(&mut z[done..], &x[done..], y);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(seed: &mut u64) -> u8 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 33) as u8
    }

    #[test]
    fn simd_matches_scalar_for_many_lengths_and_multipliers() {
        let mut seed = 0x5eed_u64;
        for len in [
            0usize, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 255, 256, 7424, 7425,
        ] {
            for y in [0u8, 1, 2, 3, 7, 16, 100, 128, 200, 254, 255] {
                let x: Vec<u8> = (0..len).map(|_| lcg(&mut seed)).collect();
                let z0: Vec<u8> = (0..len).map(|_| lcg(&mut seed)).collect();
                let mut want = z0.clone();
                addmul_scalar(&mut want, &x, y);
                let mut got = z0.clone();
                addmul(&mut got, &x, y);
                assert_eq!(got, want, "len {len} y {y}");
            }
        }
    }

    #[test]
    fn nibble_tables_are_linear_decomposition() {
        let g = gf();
        for y in 0..=255u8 {
            let (lo, hi) = nibble_tables(y);
            for x in 0..=255u8 {
                assert_eq!(
                    lo[(x & 0x0f) as usize] ^ hi[(x >> 4) as usize],
                    g.mul[y as usize][x as usize]
                );
            }
        }
    }

    /// `cargo test -p storj-ec --release -- --ignored addmul_throughput --nocapture`
    #[test]
    #[ignore]
    fn addmul_throughput() {
        let x = vec![0xa5u8; 7424 * 64];
        let mut z = vec![0x5au8; x.len()];
        let iters = 2000;
        let t = std::time::Instant::now();
        for i in 0..iters {
            addmul(&mut z, &x, (i % 254 + 1) as u8);
        }
        let secs = t.elapsed().as_secs_f64();
        let mb = (x.len() as f64 * iters as f64) / (1024.0 * 1024.0);
        println!("addmul (simd dispatch): {:.0} MB/s", mb / secs);
        let t = std::time::Instant::now();
        for i in 0..iters {
            addmul_scalar(&mut z, &x, (i % 254 + 1) as u8);
        }
        let secs = t.elapsed().as_secs_f64();
        println!("addmul (scalar):        {:.0} MB/s", mb / secs);
    }
}
