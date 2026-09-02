//! Object Lock: retention, legal hold, and bucket lock configuration.

use std::time::{SystemTime, UNIX_EPOCH};

use storj_encryption::encrypt_path;
use storj_proto::metainfo::{
    DefaultRetention as ProtoDefaultRetention, ObjectLockConfiguration,
    Retention as ProtoRetention, default_retention, retention,
};

use crate::bucket::{proto_timestamp, require_bucket_name};
use crate::error::{Error, ErrorKind, Result};
use crate::project::{Project, require_object_key};
use crate::types::{
    BucketObjectLockConfiguration, DefaultRetention, Retention, RetentionMode,
    SetObjectRetentionOptions,
};

impl Project {
    /// Get object retention (Object Lock). `None` if the object has no retention.
    pub async fn get_object_retention(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
    ) -> Result<Option<Retention>> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let encrypted = self.encrypt_object_key(bucket, key)?;
        self.inner
            .metainfo
            .get_object_retention(bucket, &encrypted, version.unwrap_or(&[]), key)
            .await
    }

    /// Set object retention (Object Lock).
    pub async fn set_object_retention(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
        retention: Retention,
        opts: SetObjectRetentionOptions,
    ) -> Result<()> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let encrypted = self.encrypt_object_key(bucket, key)?;
        self.inner
            .metainfo
            .set_object_retention(
                bucket,
                &encrypted,
                version.unwrap_or(&[]),
                &retention,
                opts.bypass_governance_retention,
                key,
            )
            .await
    }

    /// Get object legal hold.
    pub async fn get_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
    ) -> Result<bool> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let encrypted = self.encrypt_object_key(bucket, key)?;
        self.inner
            .metainfo
            .get_object_legal_hold(bucket, &encrypted, version.unwrap_or(&[]), key)
            .await
    }

    /// Set object legal hold.
    pub async fn set_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&[u8]>,
        enabled: bool,
    ) -> Result<()> {
        require_bucket_name(bucket)?;
        require_object_key(key)?;
        let encrypted = self.encrypt_object_key(bucket, key)?;
        self.inner
            .metainfo
            .set_object_legal_hold(bucket, &encrypted, version.unwrap_or(&[]), enabled, key)
            .await
    }

    /// Get bucket Object Lock configuration.
    pub async fn get_bucket_object_lock_configuration(
        &self,
        bucket: &str,
    ) -> Result<BucketObjectLockConfiguration> {
        require_bucket_name(bucket)?;
        self.inner
            .metainfo
            .get_bucket_object_lock_configuration(bucket)
            .await
    }

    /// Set bucket Object Lock configuration.
    pub async fn set_bucket_object_lock_configuration(
        &self,
        bucket: &str,
        config: BucketObjectLockConfiguration,
    ) -> Result<()> {
        require_bucket_name(bucket)?;
        if let Some(default) = &config.default_retention
            && default.days > 0
            && default.years > 0
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                "bucket object lock configuration is invalid",
            ));
        }
        self.inner
            .metainfo
            .set_bucket_object_lock_configuration(bucket, &config)
            .await
    }

    fn encrypt_object_key(&self, bucket: &str, key: &str) -> Result<Vec<u8>> {
        encrypt_path(bucket, key, &self.inner.store).map_err(map_enc_err)
    }
}

pub(crate) fn retention_to_proto(r: &Retention) -> ProtoRetention {
    ProtoRetention {
        mode: retention_mode_to_proto(r.mode),
        retain_until: Some(timestamp_from_system(r.retain_until)),
    }
}

pub(crate) fn retention_from_proto(r: ProtoRetention) -> Result<Retention> {
    Ok(Retention {
        mode: retention_mode_from_proto(r.mode)?,
        retain_until: proto_timestamp(r.retain_until),
    })
}

pub(crate) fn lock_config_to_proto(cfg: &BucketObjectLockConfiguration) -> ObjectLockConfiguration {
    ObjectLockConfiguration {
        enabled: cfg.enabled,
        default_retention: cfg
            .default_retention
            .as_ref()
            .map(default_retention_to_proto),
    }
}

pub(crate) fn lock_config_from_proto(
    cfg: ObjectLockConfiguration,
) -> Result<BucketObjectLockConfiguration> {
    Ok(BucketObjectLockConfiguration {
        enabled: cfg.enabled,
        default_retention: cfg
            .default_retention
            .map(default_retention_from_proto)
            .transpose()?,
    })
}

fn default_retention_to_proto(d: &DefaultRetention) -> ProtoDefaultRetention {
    let duration = if d.days > 0 {
        Some(default_retention::Duration::Days(d.days))
    } else if d.years > 0 {
        Some(default_retention::Duration::Years(d.years))
    } else {
        None
    };
    ProtoDefaultRetention {
        mode: retention_mode_to_proto(d.mode),
        duration,
    }
}

fn default_retention_from_proto(d: ProtoDefaultRetention) -> Result<DefaultRetention> {
    let (days, years) = match d.duration {
        Some(default_retention::Duration::Days(n)) => (n, 0),
        Some(default_retention::Duration::Years(n)) => (0, n),
        None => (0, 0),
    };
    Ok(DefaultRetention {
        mode: retention_mode_from_proto(d.mode)?,
        days,
        years,
    })
}

fn retention_mode_to_proto(mode: RetentionMode) -> i32 {
    match mode {
        RetentionMode::Compliance => retention::Mode::Compliance as i32,
        RetentionMode::Governance => retention::Mode::Governance as i32,
    }
}

fn retention_mode_from_proto(mode: i32) -> Result<RetentionMode> {
    match mode {
        m if m == retention::Mode::Compliance as i32 => Ok(RetentionMode::Compliance),
        m if m == retention::Mode::Governance as i32 => Ok(RetentionMode::Governance),
        _ => Err(Error::new(
            ErrorKind::Protocol,
            format!("invalid retention mode {mode}"),
        )),
    }
}

fn timestamp_from_system(t: SystemTime) -> prost_types::Timestamp {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    prost_types::Timestamp {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
    }
}

fn map_enc_err(e: storj_encryption::Error) -> Error {
    let kind = match e.kind() {
        storj_encryption::ErrorKind::DecryptionFailed => ErrorKind::DecryptionFailed,
        storj_encryption::ErrorKind::MissingEncryptionBase
        | storj_encryption::ErrorKind::MissingDecryptionBase => ErrorKind::InvalidGrant,
        _ => ErrorKind::Protocol,
    };
    Error::new(kind, e.to_string()).with_source(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn retention_mode_round_trip() {
        for mode in [RetentionMode::Compliance, RetentionMode::Governance] {
            let proto = retention_mode_to_proto(mode);
            assert_eq!(retention_mode_from_proto(proto).unwrap(), mode);
        }
        assert_eq!(
            retention_mode_from_proto(retention::Mode::Invalid as i32)
                .unwrap_err()
                .kind(),
            ErrorKind::Protocol
        );
    }

    #[test]
    fn retention_timestamp_round_trip() {
        let r = Retention {
            mode: RetentionMode::Governance,
            retain_until: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        };
        let back = retention_from_proto(retention_to_proto(&r)).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn default_retention_days_and_years() {
        let days = DefaultRetention {
            mode: RetentionMode::Compliance,
            days: 30,
            years: 0,
        };
        let pb = default_retention_to_proto(&days);
        assert_eq!(pb.duration, Some(default_retention::Duration::Days(30)));
        assert_eq!(default_retention_from_proto(pb).unwrap(), days);

        let years = DefaultRetention {
            mode: RetentionMode::Governance,
            days: 0,
            years: 2,
        };
        let pb = default_retention_to_proto(&years);
        assert_eq!(pb.duration, Some(default_retention::Duration::Years(2)));
        assert_eq!(default_retention_from_proto(pb).unwrap(), years);
    }

    #[test]
    fn lock_config_omits_default_when_none() {
        let cfg = BucketObjectLockConfiguration {
            enabled: true,
            default_retention: None,
        };
        let pb = lock_config_to_proto(&cfg);
        assert!(pb.enabled);
        assert!(pb.default_retention.is_none());
        assert_eq!(lock_config_from_proto(pb).unwrap(), cfg);
    }

    #[test]
    fn empty_object_key_is_invalid() {
        let e = crate::project::require_object_key("").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ObjectKeyInvalid);
        assert!(e.to_string().contains(r#"("")"#), "{e}");
        crate::project::require_object_key("k").unwrap();
    }
}
