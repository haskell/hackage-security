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
