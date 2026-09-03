# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

Email **bradk@vitalsoft.com** with a description of the issue, its impact, and
a reproduction if possible. You should receive an acknowledgement, and we will
keep you informed while a fix is prepared.

This crate handles access grants, encryption keys, and object data. Treat grant
strings and encryption keys as secrets. Do not commit production grants; the
checked-in fixtures in `crates/storj/tests/fixtures/` are synthetic (see that
directory's README).

## Supported versions

The `main` branch and the latest `1.x` git tag receive security fixes.
