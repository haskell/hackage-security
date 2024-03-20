See also http://pvp.haskell.org/faq

Unreleased
----------

* Drop flag `use-network-uri` and support for `network-2.5`.


0.6.2.5
-------

* Allow `Cabal-3.12` and `Cabal-syntax-3.12`.
* Allow `zlib-0.7`.
* Drop flag `use-old-time` and support for `old-time`, require `time ≥ 1.5`
  ([PR #304](https://github.com/haskell/hackage-security/pull/304)).
* Drop support for GHC < 8.4
  ([PR #306](https://github.com/haskell/hackage-security/pull/306)).
* Code maintenance: address warning `star-is-type`, `unused-record-wildcards` etc.
  ([PR #306](https://github.com/haskell/hackage-security/pull/306)).
* Tested with GHC 8.4 - 9.8.

0.6.2.4
-------

* Allow `tar-0.6`
* Drop support for GHC < 7.8 in favor of `PatternSynonyms`
* Drop flags `base48`, `mtl21`, `old-directory` and support for GHC 7.8, `mtl < 2.2` and `directory < 1.2`
* Tested with GHC 7.10 - 9.8

0.6.2.3
-------

* Bump base for GHC 9.4 comp
* Fix code to *really* support mtl-2.3

0.6.2.2
-------

* Fix broken compilation of test-suite with Cabal-syntax-3.8.1.0 on Hackage
* Huge README updates

0.6.2.1
-------

* Allow GHC-9.0 (base-4.15) (#265)
* Fix running `cabal repl hackage-security` (#263)

0.6.2.0
-------

* Safely prepare for when cabal factors out Cabal-syntax

0.6.1.0
-------

* Support basic auth in package-indices (#252)
* Fix tests due to new aeson handling of unescaped control sequences (#256)
* Bump a lot of bounds on packages we depend on

0.6.0.1
-------

* Fix bug in non-default `-lukko` build-configuration (#242)
* Add support for `template-haskell-2.16.0.0` (#240)

0.6.0.0
-------

* Remove `Hackage.Security.TUF.FileMap.lookupM`
* Don't expose `Hackage.Security.Util.IO` module
* Don't expose `Hackage.Security.Util.Lens` module
* Report missing keys in `.meta` objects more appropriately as
  `ReportSchemaErrors(expected)` instead of via `Monad(fail)`
* Add support for GHC 8.8 / base-4.13
* Use `lukko` for file-locking
* Extend `LogMessage` to signal events for cache lock acquiring and release
* New `lockCacheWithLogger` operation

0.5.3.0
-------

* Use `flock(2)`-based locking where available
  (compat-shim taken from `cabal-install`'s code-base) (#207)
* Improve handling of async exceptions (#187)
* Detect & recover from local corruption of uncompressed index tarball (#196)
* Support `base-4.11`

0.5.2.2
-------

* Fix client in case where server provides MD5 hashes
  (ignore them, use only SHA256)
* Fix warnings with GHC 8

0.5.2.1
-------

* Fix accidental breakage with GHC 8

0.5.2.0
-------

* Change path handling to work on Windows (#162).
* Add new MD5 hash type (#163). This is not for security (only SHA256 is
  used for verification) but to provide as metadata to help with other
  services like mirroring (e.g. HTTP & S3 use MD5 checksum headers).
* Adjust reading of JSON maps to ignore unknown keys. This allows adding
  e.g. new hash types in future without breaking existing clients.
* Fix build warnings on GHC 8


0.5.1.0
-------

* Fix for other local programs corrputing the 00-index.tar. Detect it
  and do a full rewrite rather than incremental append.
* New JSON pretty-printer (not canonical rendering)
* Round-trip tests for Canonical JSON parser and printers
* Minor fix for Canonical JSON parser
* Switch from cryptohash to cryptohash-sha256 to avoid new dependencies

0.5.0.2
-------
* Use tar 0.5.0
* Relax lower bound on directory

0.5.0.1
-------
* Relaxed dependency bounds

0.5.0.0
-------
* Treat deserialization errors as verification errors (#108, #75)
* Avoid `Content-Length: 0` in GET requests (#103)
* Fix bug in Trusted
* Build tar-index incrementally (#22)
* Generalize 'Repository' over the representation of downloaded remote files.
* Update index incrementally by downloading delta of `.tar.gz` and writing only
  tail of local `.tar` file (#101). Content compression no longer used.
* Take a lock on the cache directory before updating it, and no longer use
  atomic file ops (pointless since we now update some files incrementally)
* Code refactoring/simplification.
* Support for ed25519 >= 0.0.4
* `downloadPackage` no longer takes a callback.
* API for accessing the Hackage index contents changed; it should now be
  easier for clients to do their own incremental updates should they wish
  to do so.
* Relies on tar >= 0.4.4
* Removed obsolete option for downloading the compressed index (we now _always_
  download the compressed index)
* Path module now works on Windows (#118)
* Dropped support for ghc 7.2
* Replaced uses of Int with Int54, to make sure canonical JSON really is
  canonical (#141).

0.4.0.0
-------
* Allow clients to pass in their own time for expiry verification
  (this is an API change hence the major version bump)
* Export .Client.Formats (necessary to define new Repositories)
* Start work on basic test framework

0.3.0.0
-------
* Don't use compression for range requests (#101)
* Download index.tar.gz, not index.tar, if range request fails (#99)
* Minor change in the LogMessage type (hence the API version bumb)
* Include ChangeLog.md in the tarball (#98)

0.2.0.0
-------
* Allow for network-2.5 (rather than network-uri-2.6)
* Use cryptohash rather than SHA
* Various bugfixes
* API change: introduce RepoOpts in the Remote repository

0.1.0.0
-------
* Initial beta release
