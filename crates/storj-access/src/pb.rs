//! Prost types matching vendored `proto/{encryption,encryption_access,scope}.proto`
//! (generated in `storj-proto`; do not invent fields).

pub use storj_proto::encryption::{CipherSuite, EncryptionParameters};
pub use storj_proto::encryption_access::EncryptionAccess;
pub use storj_proto::encryption_access::encryption_access::StoreEntry;
pub use storj_proto::scope::Scope;
