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

//! GF(2^8) tables matching `storj.io/infectious` (poly 0x11d, generator 2).
//!
//! Port of infectious `tables.go` / `math.go` / `addmul`. Same field as AES /
//! Klaus Post; the encoding *matrix* is Rizzo/zfec, not Backblaze (see `fec`).

use std::sync::LazyLock;

/// Primitive polynomial x^8 + x^4 + x^3 + x^2 + 1.
const POLY: u16 = 0x11d;

pub(crate) struct Tables {
    pub exp: [u8; 510],
    /// Used to build `mul` / `inverse`; kept for infectious-table assertions.
    #[allow(dead_code)]
    pub log: [u8; 256],
    pub inverse: [u8; 256],
    pub mul: [[u8; 256]; 256],
}

static TABLES: LazyLock<Tables> = LazyLock::new(build_tables);

pub(crate) fn gf() -> &'static Tables {
    &TABLES
}

fn build_tables() -> Tables {
    let mut exp = [0u8; 510];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for (i, slot) in exp.iter_mut().enumerate().take(255) {
        *slot = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
    }
    let (lo, hi) = exp.split_at_mut(255);
    hi.copy_from_slice(lo);
    log[0] = 0xff;

    let mut inverse = [0u8; 256];
    inverse[0] = 0;
    for i in 1..256 {
        inverse[i] = exp[255 - log[i] as usize];
    }

    let mut mul = [[0u8; 256]; 256];
    for i in 0..256 {
        for j in 0..256 {
            mul[i][j] = exp[(log[i] as usize + log[j] as usize) % 255];
        }
    }
    for row in &mut mul {
        row[0] = 0;
    }
    mul[0] = [0u8; 256];

    Tables {
        exp,
        log,
        inverse,
        mul,
    }
}

/// `z[i] ^= y * x[i]` over GF(2^8). `x` must be at least as long as `z`.
/// Vectorized on aarch64 (NEON) and x86_64 (SSSE3, runtime-detected); see
/// [`crate::gf_simd`].
#[inline]
pub(crate) fn addmul(z: &mut [u8], x: &[u8], y: u8) {
    crate::gf_simd::addmul(z, x, y)
}

/// Inverted Vandermonde used to build the systematic encoding matrix.
/// Port of infectious `createInvertedVdm`.
pub(crate) fn create_inverted_vdm(vdm: &mut [u8], k: usize) {
    if k == 1 {
        vdm[0] = 1;
        return;
    }
    let gf = gf();
    let mut b = vec![0u8; k];
    let mut c = vec![0u8; k];
    for i in 1..k {
        let mul_p_i = &gf.mul[gf.exp[i] as usize];
        for j in (k - i)..(k - 1) {
            c[j] ^= mul_p_i[c[j + 1] as usize];
        }
        c[k - 1] ^= gf.exp[i];
    }
    for row in 0..k {
        let index = if row == 0 { 0 } else { gf.exp[row] as usize };
        let mul_p_row = &gf.mul[index];
        let mut t = 1u8;
        b[k - 1] = 1;
        for i in (0..k - 1).rev() {
            b[i] = c[i + 1] ^ mul_p_row[b[i + 1] as usize];
            t = b[i] ^ mul_p_row[t as usize];
        }
        let mul_t_inv = &gf.mul[gf.inverse[t as usize] as usize];
        for col in 0..k {
            vdm[col * k + row] = mul_t_inv[b[col] as usize];
        }
    }
}

/// Gauss-Jordan invert of a `k × k` row-major matrix. Infectious `invertMatrix`.
pub(crate) fn invert_matrix(matrix: &mut [u8], k: usize) -> Result<(), &'static str> {
    let mut ipiv = vec![false; k];
    let mut indxc = vec![0usize; k];
    let mut indxr = vec![0usize; k];
    let mut id_row = vec![0u8; k];

    for col in 0..k {
        let (icol, irow) = search_pivot(&mut ipiv, col, matrix, k)?;
        if irow != icol {
            for i in 0..k {
                matrix.swap(irow * k + i, icol * k + i);
            }
        }
        indxr[col] = irow;
        indxc[col] = icol;
        let mut pivot_row = matrix[icol * k..icol * k + k].to_vec();
        let mut c = pivot_row[icol];
        if c == 0 {
            return Err("singular matrix");
        }
        if c != 1 {
            c = gf().inverse[c as usize];
            pivot_row[icol] = 1;
            let mul_c = &gf().mul[c as usize];
            for p in &mut pivot_row {
                *p = mul_c[*p as usize];
            }
        }
        matrix[icol * k..icol * k + k].copy_from_slice(&pivot_row);

        id_row[icol] = 1;
        if pivot_row != id_row {
            for i in 0..k {
                if i != icol {
                    let coeff = matrix[i * k + icol];
                    matrix[i * k + icol] = 0;
                    addmul(&mut matrix[i * k..i * k + k], &pivot_row, coeff);
                }
            }
        }
        id_row[icol] = 0;
    }

    for i in 0..k {
        if indxr[i] != indxc[i] {
            for row in 0..k {
                matrix.swap(row * k + indxr[i], row * k + indxc[i]);
            }
        }
    }
    Ok(())
}

fn search_pivot(
    ipiv: &mut [bool],
    col: usize,
    matrix: &[u8],
    k: usize,
) -> Result<(usize, usize), &'static str> {
    if !ipiv[col] && matrix[col * k + col] != 0 {
        ipiv[col] = true;
        return Ok((col, col));
    }
    for row in 0..k {
        if ipiv[row] {
            continue;
        }
        for i in 0..k {
            if !ipiv[i] && matrix[row * k + i] != 0 {
                ipiv[i] = true;
                // infectious returns (icol, irow) = (row, i)
                return Ok((row, i));
            }
        }
    }
    Err("pivot not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infectious_exp_log_inverse() {
        let g = gf();
        assert_eq!(g.exp[0], 0x01);
        assert_eq!(g.exp[1], 0x02);
        assert_eq!(g.exp[7], 0x80);
        assert_eq!(g.exp[8], 0x1d);
        assert_eq!(g.log[0], 0xff);
        assert_eq!(g.log[1], 0x00);
        assert_eq!(g.log[2], 0x01);
        assert_eq!(g.inverse[0], 0x00);
        assert_eq!(g.inverse[1], 0x01);
        assert_eq!(g.inverse[2], 0x8e);
        assert_eq!(g.exp[255], 0x01);
    }

    #[test]
    fn mul_zero_and_one() {
        let g = gf();
        for i in 0..256 {
            assert_eq!(g.mul[0][i], 0);
            assert_eq!(g.mul[i][0], 0);
            assert_eq!(g.mul[1][i], i as u8);
            assert_eq!(g.mul[i][1], i as u8);
        }
    }
}
