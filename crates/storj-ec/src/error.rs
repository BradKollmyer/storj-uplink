//! Errors from Reed-Solomon encode/decode.

/// Erasure-coding failure. Independent of `storj::Error` (no network).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// `k`, `n`, or `share_size` is outside the infectious limits.
    #[error(
        "requires 1 <= k <= n <= 256 and share_size > 0 (k={k}, n={n}, share_size={share_size})"
    )]
    InvalidParams {
        /// Required shares.
        k: usize,
        /// Total shares.
        n: usize,
        /// Bytes per share.
        share_size: usize,
    },
    /// Stripe is not exactly `k * share_size` bytes.
    #[error("stripe length {got} != k*share_size {want}")]
    StripeSize {
        /// Actual stripe length.
        got: usize,
        /// Expected stripe length.
        want: usize,
    },
    /// A share is the wrong length.
    #[error("share {index} length {got} != share_size {want}")]
    ShareSize {
        /// Share index.
        index: usize,
        /// Actual length.
        got: usize,
        /// Expected length.
        want: usize,
    },
    /// Decoder was given fewer than `k` shares.
    #[error("not enough shares: have {have}, need {need}")]
    TooFewShares {
        /// Shares supplied.
        have: usize,
        /// Shares required (`k`).
        need: usize,
    },
    /// Share index is not in `0..n`.
    #[error("invalid share index {index} (n={n})")]
    InvalidShareIndex {
        /// Offending index.
        index: usize,
        /// Total shares.
        n: usize,
    },
    /// The same share index appeared twice.
    #[error("duplicate share index {index}")]
    DuplicateShare {
        /// Duplicated index.
        index: usize,
    },
    /// `decode_stripe` expects `n` slots.
    #[error("need {n} share slots, got {got}")]
    ShareCount {
        /// Slots supplied.
        got: usize,
        /// Slots required (`n`).
        n: usize,
    },
    /// Matrix inversion failed (singular / no pivot).
    #[error("reconstruction failed: {0}")]
    Reconstruct(&'static str),
}

/// Result alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
