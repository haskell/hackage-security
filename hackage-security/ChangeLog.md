0.5.0.0
-------
* Treat deserialization errors as verification errors (#108, #75)
* Avoid `Content-Length: 0` in GET requests (#103)
* Fix bug in Trusted
* Build tar-index incrementally (#22)
* Generalize 'Repository' over the representation of downloaded remote files.
* Update index incrementally by downloading delta of `.tar.gz` and writing only
  tail of local `.tar` file (#101)
* Take a lock on the cache directory before updating it, and no longer use
  atomic file ops (pointless since we now update some files incrementally)
* Code refactoring/simplification.
* Support for ed25519 >= 0.0.4
* `downloadPackage` no longer takes a callback.
* API for accessing the Hackage index contents changed; it should now be
  easier for clients to do their own incremental updates should they wish
  to do so.

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
