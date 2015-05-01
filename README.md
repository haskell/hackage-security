# Hackage Security

This is a library for Hackage security based on
[TUF, The Update Framework](http://theupdateframework.com/).

## Comparison with TUF

In this section we highlight some of the differences in the specifics of the
implementation; generally we try to follow the TUF model as precisely as
possible.
This section is not (currently) intended to be complete.

### Targets

#### Package versions

Each version of each package is stored in a directory `targets/Foo/1.0` which
contains a `targets.json` which is specfic to this version of this package,
containing precisely two entries:

```
{ "signed" : {
      "_type"   : "Targets"
    , "version" : VERSION
    , "expires" : EXPIRES
    , "targets" : {
          "Foo-1.0.tar.gz" : FILEINFO
        , "Foo-1.0.cabal"  : FILEINFO
       }
, "signatures" : <signatures from package maintainers>
}
```

where the SIGNATURES must be signed by the package maintainers (once we add
support for that). In addition it contains a file `revisions.json` which
revisions of the Cabal file:

```
{ "signed" : {
      "_type"   : "Targets"
    , "version" : VERSION
    , "expires" : EXPIRES
    , "targets" : {
          "Foo-1.0-rev1.cabal"  : FILEINFO
        , "Foo-1.0-rev2.cabal"  : FILEINFO
       }
, "signatures" : <signatures from package maintainers or trustees>
}
```

This file is either signed by the package authors or by the Hackage trustees.

#### Packages

For each package we record a single `targets.json` in `Foo/targets.json` with
delegation information:

```
{ signed : {
      "_type"       : "Targets"
    , "version"     : VERSION
    , "expires"     : EXPIRES
    , "targets"     : {}
    , "delegations" : {
          "keys"  : <package maintainer keys>
        , "roles" : [{
               "name"      : "*/targets.json"
             , "keyids"    : <package maintainer key IDs>
             , "threshold" : THRESHOLD
             , "paths"     : "*/*"
            }, {
               "name"      : "*/revisions.json"
             , "keyids"    : <package maintainer key IDs and trustee key IDs>
             , "threshold" : THRESHOLD
             , "paths"     : "*/*.cabal"
            }]
    }
, "signatures" : <signatures from top level target keys>
}
```

This uses a minor extension to TUF: we can use globs to specify path patterns,
and then refer to the matching wildcards in the role name. This means that we
don't need to change this file whenever a new package version is uploaded.

This file is signed by the Hackage admins, using offline top-level targets keys.
The "keys" part of "delegations" lists this package maintainer keys (if any).
Then it lists two roles:

1. It lists that any file can be recorded in the package version's
   `targets.json`; the key IDs here should equal the list of package
   maintainer keys. The threshold can be set to 0 for packages for which
   we do not use author signing (or before we have added support for author
   signing).

2. It lists that the `.cabal` files can be signed in the `revisions.json`.
   The key IDs here should equal the list of package maintainer keys plus
   the list of Hackage trustees keys. If we have not yet implemented author
   signing, then we can just leave this list blank and set the threshold to 0.

#### Top-level

The top-level `targets.json` lists only delegation information.

```
{ signed: {
      "_type"       : "Targets"
    , "version"     : VERSION
    , "expires"     : EXPIRES
    , "targets"     : {}
    , "delegations" : {
          "keys"  : []
        , "roles" : [{
               "name"      : "*/targets.json"
             , "keyids"    : <top-level target keys>
             , "threshold" : THRESHOLD
             , "paths"     : "*/*/*"
            }]
    }
, "signatures" : <signatures from top level target keys>
}
```

This lists that any path at all (such as `/Foo/1.0/Foo-1.0.gz`) will have
it's delegation information in `Foo/targets.json`.

Note that this does not introduce any new keys; this file is signed by the
Hackage admins (using off-line top-level target keys), and delegates to files
signed with those same keys. The point of this delegation is not security, but
rather to reduce the granularity of the files that require updating whenever we
update something.

The way we've set things up, when a brand new package is introduced to Hackage,
the Hackage admins need to sign only a single `targets.json` file
(`NewFoo/targets.json`); similarly, for every new version that is added, authors
only need to sign `NewFoo/2.0/targets.json` (and trustees only need to sign the
`revisions.json` file when they make add a new `.cabal` file revision).

### Snapshot

#### Interaction with the index tarball

According to the official specification we should have a file `snapshot.json`,
signed with the snapshot key, which lists the hashes of _all_ metadata files
in the repo. In Hackage however we have the index tarball, which _contains_
all metadata files in the repo (that is, it contains all the `.cabal` files,
but it also contains all the `targets.json` files, as well as the `root.json`
file). The only thing that is missing from the index tarball, compared to the
`snapshot.json` file from the TUF spec, is the version, expiry time, and
signatures. Therefore our `snapshot.json` looks like

```
{ "signed" : {
      "_type"   : "Snapshot"
    , "version" : VERSION
    , "expires" : EXPIRES
    , "meta"    : {
           "index.tar"    : FILEINFO
         , "index.tar.gz" : FILEINFO
        }
    }
, "signatures" : <signatures from snapshot key>
}
```

Then the combination of `snapshot.json` together with the index tarball is
a strict superset of the information in TUF's `snapshot.json` (instead of
containing the hashes of the metadata in the repo, it contains the actual
metadata themselves).

#### Efficiency of requests

Since our `snapshot.json` contains only a single entry (corresponding to the
index tarball), it becomes very similar to in function to `timestamp.json`.
However, it is logically different and signed with a different key. Admittedly,
in our current setup both the timestamp and the snapshot keys will be kept on
the same server, but this may not be the case in the future.  

In order to keep the comparison with TUF as clear as possible we will keep
these files separate. However, since the size of our `snapshot.json` is
essentially fixed (unlike in standard TUF) we can safely download both the
timestamp and the snapshot in one go, without exposing ourselves to a
potential endless data attack. To make the initial HTTP request more efficient,
we can easily bundle both `timestamp.json` and `snapshot.json` in a single JSON
file:

```
{ "timestamp.json": { "signed": ..., "signatures": ... }
, "snapshot.json" : { "signed": ..., "signatures": ... }
}
```
