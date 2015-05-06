# Hackage Security

This is a library for Hackage security based on
[TUF, The Update Framework](http://theupdateframework.com/).

## Comparison with TUF

In this section we highlight some of the differences in the specifics of the
implementation; generally we try to follow the TUF model as closely as
possible.

This section is not (currently) intended to be complete.

### Targets

In the current proposal we do not yet implement author signing, but when we do
implement author signing we want to have a smooth transition, and moreover we
want to be able to have a mixture of packages, some of which are author signed
and some of which are not. That is, package authors must be able to opt-in to
author signing (or not).

#### Unsigned packages

##### Package specific metadata

Unsigned packages will be stored in `unsigned/`. Version 1.0 of package `Foo`
will be stored in `unsigned/Foo/1.0`. This directory will contain a single
metadata file containing hashes and sizes of the package tarball and the
`.cabal` files:

```
{ "signed" : {
     "_type"   : "Targets"
   , "version" : VERSION
   , "expires" : never
   , "targets" : {
         "Foo-1.0.tar.gz"     : FILEINFO
       , "Foo-1.0.cabal"      : FILEINFO
       , "Foo-1.0-rev1.cabal" : FILEINFO
       , "Foo-1.0-rev2.cabal" : FILEINFO
       , ...
       }
   }
, "signatures" : []
}
```

Note that expiry dates are relevant only for information that we expect to
change over time (such as the snapshot). Since packages are immutable, they
cannot expire.

##### Delegation

We then have a top-level `targets.json` that contains the required delegation
information:

```
{ "signed" : {
      "_type"       : Targets
    , "version"     : VERSION
    , "expires"     : never
    , "targets"     : []
    , "delegations" : {
          "keys"  : []
        , "roles" : [
               { "name"      : "unsigned/*/*/targets.json"
               , "keyids"    : []
               , "threshold" : 0
               , "path"      : "unsigned/*/*/*"
               }
             ]
       }
    }
, "signatures" : <target keys>
}
```

This file itself is signed by the target keys (kept offline by the Hackage
admins).  

<blockquote>
_Deviation from TUF spec_
This uses an extension to the TUF spec where we can use wildcards in names as
well as in paths. This means that we list a **single** path with a **single**
replacement name. Alternatively, we could have a list of pairs of paths and
names.)
</blockquote>

New unsigned packages, as well as new versions of existing unsigned packages,
can be uploaded to Hackage without any intervention from the Hackage admins (the
offline target keys are not required).

##### Security

As per the TUF specification, the hash and size of _all_ metadata files (which
therefore includes package specific `unsigned/Foo/1.0/targets.json`) is listed
in the snapshot. This means that untrusted mirrors or man-in-the-middle attacks
cannot change which packages are visible or change the packages themselves.

However, since the snapshot key is stored on the server, if the server itself is
compromised almost all security guarantees are void.

#### Signed packages

(We sketch the design here only, we do not actually intend to implement this yet
in phase 1 of the project.)

##### Package specific metadata

Signed packages are stored in the directory `signed/`. As for unsigned packages,
we keep metadata specific for each package version. Unlike for unsigned
packages, however, we store two files: one that can be signed by the package
author, and one that can be signed by the Hackage trustees, which can upload new
`.cabal` file revisions but not change the package contents.

Thus we have `targets.json`, containing precisely two entries:

```
{ "signed" : {
     "_type"   : "Targets"
   , "version" : VERSION
   , "expires" : never
   , "targets" : {
         "Foo-1.0.tar.gz"     : FILEINFO
       , "Foo-1.0.cabal"      : FILEINFO
       }
   }
, "signatures" : <signatures from package authors>
}
```

and `revisions.json`:

```
{ "signed" : {
     "_type"   : "Targets"
   , "version" : VERSION
   , "expires" : never
   , "targets" : {
       , "Foo-1.0-rev1.cabal" : FILEINFO
       , "Foo-1.0-rev2.cabal" : FILEINFO
       , ...
       }
   }
, "signatures" : <signatures from package authors or Hackage trustees>
}
```

##### Delegation

Delegation for signed packages is a bit more complicated. We extend the
top-level targets file to

```
{ "signed" : {
      "_type"       : Targets
    , "version"     : VERSION
    , "expires"     : never
    , "targets"     : []
    , "delegations" : {
          "keys"  : <Hackage trustee keys>
        , "roles" : [
               { "name"      : "unsigned/*/*/targets.json"
               , "keyids"    : []
               , "threshold" : 0
               , "path"      : "unsigned/*/*/*"
               }
             , { "name"      : "signed/*/targets.json"
               , "keyids"    : <top-level target keys>
               , "threshold" : THRESHOLD
               , "path"      : "signed/*/*/*"
               }
             , { "name"      : "signed/*/*/revisions.json"
               , "keyids"    : <Hackage trustee key IDs>
               , "threshold" : THRESHOLD
               , "path"      : "signed/*/*/*.cabal"
               }
             ]
       }
    }
, "signatures" : <target keys>
}
```

This indicates that all cabal files for package `Foo-1.0` are listed in
`signed/Foo/1.0/revisions.json`, and that this file must be signed by the
Hackage trustees. In addition, it says that any file in `signed/Foo/1.0` can
also be listed in `signed/Foo/targets.json`. This &ldquo;middle level&rdquo;
targets file contains further delegation information:

```
{ "signed" : {
      "_type"       : "Targets"
    , "version"     : VERSION
    , "expires"     : EXPIRES
    , "targets"     : {}
    , "delegations" : {
          "keys"  : <package maintainer keys>
        , "roles" : [
              { "name"      : "*/targets.json"
              , "keyids"    : <package maintainer key IDs>
              , "threshold" : THRESHOLD
              , "path"      : "*/*"
              }
            , { "name"      : "*/revisions.json"
              , "keyids"    : <package maintainer key IDs>
              , "threshold" : THRESHOLD
              , "path"      : "*/*.cabal"
              }
            ]
    }
, "signatures" : <signatures from top-level target keys>
}
```

Some notes:

1. When a new signed package is introduced, the Hackage admins need to create
   and sign a new `targets.json` that lists the package author keys and
   appropriate delegation information. However, once this is done, the Hackage
   admins do not need to be involved when package authors wish to upload
   new versions.

2. When package authors upload a new version, they need to sign only a single
   file that contains the information about that particular version.

3. Both package authors (through the package-specific &ldquo;middle level&rdquo;
   delegation information) and Hackage trustees (through the top-level
   delegation information) can sign `.cabal` file revisions, but only authors
   can sign the packages themselves.

4. Hackage trustees are listed only in the top-level delegation information, so
   when the set of trustees changes we only need to modify one file (as opposed
   to each middle-level package delegation information).

##### Transition packages from `unsigned` to `signed`

When a package that previously did not opt-in to author signing now wants
author-signing, we just need to move it from `unsigned/` to `signed/` and
set up the appropriate middle-level delegation information.

##### Security

When the snapshot key is compromised, attackers still do not have access to
package author keys, which are strictly kept offline. However, they can change
the index to record packages that were previously listed as `signed/` now as
`unsigned/`. Clients (i.e., `cabal-install`) SHOULD warn about packages that
were previously signed and are now listed as unsigned (and probably even refuse
to install such packages by default).

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

## Open questions / TODOs

* The set of maintainers of a package can change over time, and can even change
  so much that the old maintainers of a package are no longer maintainters.
  But we would still like to be able to install and verify old packages. How
  do we deal with this?

* In the spec as defined we list each revision of a cabal file separately
  (`Foo-1.0-rev1.cabal`), but in the tarball these entries actually _overwrite_
  each other (they all have the same filename). We need to define precisely
  how we deal with this.

* The threshold for Hackage trustees should probably be set to 1, but we might
  want to be able to override this for specific more sensitive packages; indeed,
  for some packages we may want to disable trustee signing completely. If we
  want that, we might want to some sort 'priority' scheme for delegation rules;
  the TUF spec mentions that this might be desirable but does not make any
  specific recommendations.
