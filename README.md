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

Version 1.0 of package `Foo` will be stored in `targets/Foo/1.0`. This directory
will contain a single metadata file `targets/Foo/1.0/targets.json` containing
hashes and sizes of the package tarball and the `.cabal` files:

``` javascript
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

``` javascript
{ "signed" : {
      "_type"       : Targets
    , "version"     : VERSION
    , "expires"     : never
    , "targets"     : []
    , "delegations" : {
          "keys"  : []
        , "roles" : [
               { "name"      : "targets/*/*/targets.json"
               , "keyids"    : []
               , "threshold" : 0
               , "path"      : "targets/*/*/*"
               }
             ]
       }
    }
, "signatures" : /* target keys */
}
```

This file itself is signed by the target keys (kept offline by the Hackage
admins).  

<blockquote>
<i>Extension to TUF spec.</i>
This uses an extension to the TUF spec where we can use wildcards in names as
well as in paths. This means that we list a <b>single</b> path with a
<b>single</b> replacement name. (Alternatively, we could have a list of pairs of
paths and names.)
</blockquote>

New unsigned packages, as well as new versions of existing unsigned packages,
can be uploaded to Hackage without any intervention from the Hackage admins (the
offline target keys are not required).

##### Security

As per the TUF specification, the hashes and sizes of _all_ metadata files
(which therefore includes package specific `targets/Foo/1.0/targets.json`) are
listed in the snapshot. This means that untrusted mirrors or man-in-the-middle
attacks cannot change which packages are visible or change the packages
themselves.

However, since the snapshot key is stored on the server, if the server itself is
compromised almost all security guarantees are void.

#### Signed packages

(We sketch the design here only, we do not actually intend to implement this yet
in phase 1 of the project.)

##### Package specific metadata

As for unsigned packages, we keep metadata specific for each package version.
Unlike for unsigned packages, however, we store two files: one that can be
signed by the package author, and one that can be signed by the Hackage
trustees, which can upload new `.cabal` file revisions but not change the
package contents.

Thus we have `targets.json`, containing precisely two entries:

``` javascript
{ "signed" : {
     "_type"   : "Targets"
   , "version" : VERSION
   , "expires" : never
   , "targets" : {
         "Foo-1.0.tar.gz" : FILEINFO
       , "Foo-1.0.cabal"  : FILEINFO
       }
   }
, "signatures" : /* signatures from package authors */
}
```

and `revisions.json`:

``` javascript
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
, "signatures" : /* signatures from package authors or Hackage trustees */
}
```

##### Delegation

Delegation for signed packages is a bit more complicated. We extend the
top-level targets file to

``` javascript
{ "signed" : {
      "_type"       : Targets
    , "version"     : VERSION
    , "expires"     : EXPIRES
    , "targets"     : []
    , "delegations" : {
          "keys"  : /* Hackage trustee keys */
        , "roles" : [
               { "name"      : "*/*/targets.json"
               , "keyids"    : []
               , "threshold" : 0
               , "path"      : "*/*/*"
               }
             // Delegation for package Bar
             , { "name"      : "targets/Bar/targets.json"
               , "keyids"    : <top-level target keys>
               , "threshold" : THRESHOLD
               , "path"      : "targets/Bar/*/*"
               }
             , { "name"      : "targets/Bar/*/revisions.json"
               , "keyids"    : <Hackage trustee key IDs>
               , "threshold" : THRESHOLD
               , "path"      : "targets/Bar/*/*.cabal"
               }
             // Delegation for package Baz
             , { "name"      : "targets/Baz/targets.json"
               , "keyids"    : <top-level target keys>
               , "threshold" : THRESHOLD
               , "path"      : "targets/Baz/*/*"
               }
             , { "name"      : "targets/Baz/*/revisions.json"
               , "keyids"    : <Hackage trustee key IDs>
               , "threshold" : THRESHOLD
               , "path"      : "targets/Baz/*/*.cabal"
               }
             // .. delegation for other signed packages ..
             ]
        }
    }
, "signatures" : /* target keys */
}
```

Since this lists all signed packages, we must list an expiry date here so that
attackers cannot mount freeze attacks (although this is somewhat less of an
issue here as freezing this list would make en entire new package, rather than
a new package version, invisible).

This says that the delegation information for package `Bar-`_x.y_ is found in
`targets/Bar/targets.json` as well as `targets/Bar/`_x.y_`/revisions.json`,
where the latter can only contain information about the `.cabal` files, not the
package itself. Note that these rules overlap with the rule for unsigned
packages, and so we need a priority scheme between rules. The TUF specification
leaves this quite open; in our case, we can implement a very simple rule: more
specific rules (rules with fewer wildcards) take precedence over less specific
rules.

This &ldquo;middle level&rdquo; targets file `targets/Bar/targets.json`
introduces the author keys and contains further delegation information:

``` javascript
{ "signed" : {
      "_type"       : "Targets"
    , "version"     : VERSION
    , "expires"     : never
    , "targets"     : {}
    , "delegations" : {
          "keys"  : /* package maintainer keys */
        , "roles" : [
              { "name"      : "*/targets.json"
              , "keyids"    : /* package maintainer key IDs */
              , "threshold" : THRESHOLD
              , "path"      : "*/*"
              }
            , { "name"      : "*/revisions.json"
              , "keyids"    : /* package maintainer key IDs */
              , "threshold" : THRESHOLD
              , "path"      : "*/*.cabal"
              }
            ]
    }
, "signatures" : /* signatures from top-level target keys */
}
```

Some notes:

1. When a new signed package is introduced, the Hackage admins need to create
   and sign a new `targets.json` that lists the package author keys and
   appropriate delegation information, as well as add corresponding entries to
   the top-level delegation file. However, once this is done, the Hackage admins
   do not need to be involved when package authors wish to upload new versions.

2. When package authors upload a new version, they need to sign only a single
   file that contains the information about that particular version.

3. Both package authors (through the package-specific &ldquo;middle level&rdquo;
   delegation information) and Hackage trustees (through the top-level
   delegation information) can sign `.cabal` file revisions, but only authors
   can sign the packages themselves.

4. Hackage trustees are listed only in the top-level delegation information, so
   when the set of trustees changes we only need to modify one file (as opposed
   to each middle-level package delegation information).

5. For signed packages that do not want to allow Hackage trustees to sign
   `.cabal` file revisions we can just omit the corresponding entry from the
   top-level delegations file.

##### Transition packages from `unsigned` to `signed`

When a package that previously did not opt-in to author signing now wants
author-signing, we just need to add the appropriate entries to the top-level
delegation file and set up the appropriate middle-level delegation information.

##### Security

When the snapshot key is compromised, attackers still do not have access to
package author keys, which are strictly kept offline. However, they can still
mount freeze attacks on packages versions, because there is no file (which is
signed with offline key) listing which versions are available.

We could increase security here by changing the middle-level `targets.json` to
remove the wildcard rule, list all versions explicitly, and change the top-level
delegation information to say that the middle-level file should be signed by
the package authors instead.

Note that we do not use a wildcard for signed packages in the top-level
`targets.json` for a similar reason: by listing all packages that we expect to
be signed explicitly, we have a list of signed packages which is signed by
offline keys (in this case, the target keys).

### Snapshot

#### Interaction with the index tarball

According to the official specification we should have a file `snapshot.json`,
signed with the snapshot key, which lists the hashes of _all_ metadata files
in the repo. In Hackage however we have the index tarball, which _contains_
all metadata files in the repo (that is, it contains all the `.cabal` files,
but it also contains all the `targets.json` files). The only thing that is
missing from the index tarball, compared to the `snapshot.json` file from the
TUF spec, is the version, expiry time, and signatures. Therefore our
`snapshot.json` looks like

``` javascript
{ "signed" : {
      "_type"   : "Snapshot"
    , "version" : VERSION
    , "expires" : EXPIRES
    , "meta"    : {
           "root.json"    : FILEINFO
         , "mirrors.json" : FILEINFO
         , "index.tar"    : FILEINFO
         , "index.tar.gz" : FILEINFO
        }
    }
, "signatures" : /* signatures from snapshot key */
}
```

Then the combination of `snapshot.json` together with the index tarball is
a strict superset of the information in TUF's `snapshot.json` (instead of
containing the hashes of the metadata in the repo, it contains the actual
metadata themselves).

We list the file info of the root and mirrors metadata explicitly, rather than
recording it in the index tarball, so that we can check them for updates during
the update process  (section 5.1, &ldquo;The Client Application&rdquo;, of the
TUF spec) without downloading the entire index tarball.

#### Efficiency of requests

Since our `snapshot.json` contains only a small and fixed number of entries, it
becomes very similar to in function to `timestamp.json`. However, it is
logically different and signed with a different key. Admittedly, in our current
setup both the timestamp and the snapshot keys will be kept on the same server,
but this may not be the case in the future.

In order to keep the comparison with TUF as clear as possible we will keep
these files separate. However, since the size of our `snapshot.json` is
essentially fixed (unlike in standard TUF) we can safely download both the
timestamp and the snapshot in one go, without exposing ourselves to a
potential endless data attack. To make the initial HTTP request more efficient,
we can easily bundle both `timestamp.json` and `snapshot.json` in a single JSON
file:

``` javascript
{ "timestamp.json": { "signed": ..., "signatures": ... }
, "snapshot.json" : { "signed": ..., "signatures": ... }
}
```

### Collections

Package collections are a new Hackage feature that's [currently in
development](http://www.well-typed.com/blog/2015/06/cabal-hackage-hacking-at-zurihac/).
We want package collections to be signed, just like anything else.

Collections will be stored under a prefix that is not a valid package name such
as `/collections$`. Like packages, they are versioned and immutable, so we have

```
/collections$/StackageNightly/2015.06.02/StackageNightly.collection
/collections$/StackageNightly/2015.06.03/StackageNightly.collection
/collections$/StackageNightly/...
/collections$/DebianJessie/...
/collections$/...
```

Now we have to balance a few design constraints:

1. As for packages, collections should be able to opt-in for author signing
   (once we support author signing), but we should also support
   not-author-signed (&ldquo;unsigned&rdquo;) collections. Moreover, it should
   be possible for people to create new unsigned collections without the
   involvement of the Hackage admins. This rules out listing all collections
   explicitly in the top-level `targets.json` (which is signed with offline
   target keys).

2. Even unsigned packages should be protected at least by the snapshot key so
   that we can trust collections from untrusted mirrors. This means that we need
   list of collections and (perhaps more importantly) lists of collections
   versions which are, directly or indirectly, signed by the snapshot role.

3. However, since new versions of collections may be released rather frequently
   (e.g., consider the nightly [Stackage](http://www.stackage.org/) releases) we
   do not want the index to change with every new collection version.

#### Unsigned collections

For unsigned collections we add a single delegation rule to the top-level `targets.json`:

``` javascript
{ "name"      : "collections$/targets.json"
, "keyids"    : /* snapshot key */
, "threshold" : 1
, "path"      : "collections$/*/*/*"
}
```

The middle-level `targets.json`, signed with the snapshot role, lists delegation rules for all available collections:

``` javascript
[ { "name"      : "StackageNightly/targets.json"
  , "keyids"    : /* snapshot key */
  , "threshold" : 1
  , "path"      : "StackageNightly/*/*"
  }
, { "name"      : "DebianJessie/targets.json"
  , "keyids"    : /* snapshot key */
  , "threshold" : 1
  , "path"      : "DebianJessie/*/*"
  }
, ...
]
```

These then finally lists all versions:

``` javascript
{ "signed" : {
     "_type"   : "Targets"
   , "version" : VERSION
   , "expires" : /* expiry */
   , "targets" : {
         "2015.06.02/StackageNightly.collection" : FILEINFO
       , "2015.06.03/StackageNightly.collection" : FILEINFO
       , ...
       }
   }
, "signatures" : /* signed with snapshot role */
}
```

This is a slightly different approach from packages, because we cannot rely on
the index to have the list of all versions; hence, we must list all versions
explicitly here rather than using wildcards.

All these target files (`collections$/targets.json` as well as
`collections$/StackageNightly/targets.json`,
`collections$/DebianJessie/targets.json`, etc.) must be listed with their hash
in the top-level snapshot. This means that the snapshot will grow linearly with
each new collection, but only with a small entry; and does not grow linearly
with each new collection version. Unless we deviate from the TUF spec, this is
unavoidable.

#### Author-signed collections

For author-signed collections we only need to make a single change. Suppose that
the `DebianJessie` collection is signed. Then we move the rule for
`DebianJessie` from `collections$/targets.json` and instead list it in the
top-level `targets.json` (introducing a signed collection necessarily requires
the involvement of the Hackage admins):

``` javascript
{ "name"      : "collections$/DebianJessie/targets.json"
, "keyids"    : /* DebianJessie maintainer keys */
, "threshold" : /* threshold */
, "path"      : "collections$/DebianJessie/*/*"
}
```

No other changes are required (apart from of course that
`collections$/DebianJessie/targets.json` will now be signed with the
`DebianJessie` maintainer keys rather than the snapshot key). As for packages,
this requires a priority scheme for delegation rules.

## Open questions / TODOs

* The set of maintainers of a package can change over time, and can even change
  so much that the old maintainers of a package are no longer maintainters.
  But we would still like to be able to install and verify old packages. How
  do we deal with this?

* In the spec as defined we list each revision of a cabal file separately
  (`Foo-1.0-rev1.cabal`), but in the tarball these entries actually _overwrite_
  each other (they all have the same filename). We need to define precisely
  how we deal with this.
