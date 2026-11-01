# Vapor Artifact Server

Vapor Artifact Server owns immutable downloadable application release bytes
and their public, signed release metadata. It does not own catalog policy,
identity, Mad Max files, or upload authorship. The Platform Server composes its
router into the single-process deployment; the same service router can also be
mounted independently by a future deployment profile.

The initial read API serves the latest channel manifest and signature, exact
immutable version manifests, signatures, and the matching `vapor.tar.gz`
archive. Publication remains an operator-managed workflow in the Platform
Server release tooling. The private signing key is never stored here or on the
VPS.

Release storage is selected with `VAPOR_UPDATES_ROOT` and defaults to
`/var/lib/vapor-server/updates`. The standalone process binds to
`VAPOR_ARTIFACT_BIND` (default `127.0.0.1:7116`) and exposes `/healthz` for
operator readiness checks.
