# `hackage-repo-tool`: Manage secure file-based package repositories

**Please refer to the [package description](https://hackage.haskell.org/package/hackage-repo-tool#description) for an overview of `hackage-repo-tool`, TUF and `hackage-security`.**

## Setting up a secure file-based repo

A file-based repository (as opposed to one running the actual [Hackage software](https://hackage.haskell.org/package/hackage-server)) is much easier to set up and will suffice for many purposes.  Note that such a local file-based package repository can be turned into a remotely accessible secure package repository by any HTTP server supporting static file serving such as Nginx or Apache httpd.

1.  Create a directory `~/my-secure-repo` containing a single
    subdirectory `~/my-secure-repo/package`. Put whatever packages you
    want to make available from your repo in this subdirectory. At this
    point your repository might look like

        ~/my-secure-repo/package/basic-sop-0.1.0.5.tar.gz
        ~/my-secure-repo/package/generics-sop-0.1.1.1.tar.gz
        ~/my-secure-repo/package/generics-sop-0.1.1.2.tar.gz
        ~/my-secure-repo/package/json-sop-0.1.0.4.tar.gz
        ~/my-secure-repo/package/lens-sop-0.1.0.2.tar.gz
        ~/my-secure-repo/package/pretty-sop-0.1.0.1.tar.gz
        ~/my-secure-repo/package/HsYAML-0.2.1.0.tar.gz

    *(Due to [#174](https://github.com/haskell/hackage-security/issues/174) this folder must contain at least one package tarball or `hackage-repo-tool` will fail in non-obvious ways)*

    Note the flat directory structure: different packages and
    different versions of those packages all live in the one
    directory.

2.  Create public and private keys:

        # hackage-repo-tool create-keys \
                            --keys ~/my-private-keys

    This will create a directory structure such as

        ~/my-private-keys/mirrors/id01.private
        ~/my-private-keys/mirrors/..
        ~/my-private-keys/root/id04.private
        ~/my-private-keys/root/..
        ~/my-private-keys/snapshot/id07.private
        ~/my-private-keys/target/id08.private
        ~/my-private-keys/target/..
        ~/my-private-keys/timestamp/id11.private

    containing keys for all the various TUF roles.

    Note that these keys are stored outside of the repository proper.

3.  Create the initial TUF metadata and construct an index using

        # hackage-repo-tool bootstrap \
                            --repo ~/my-secure-repo \
                            --keys ~/my-private-keys

    This will create a directory `~/my-secure-repo/index` containing the
    `.cabal` files (extracted from the package tarballs) and TUF
    metadata for all packages

        ~/my-secure-repo/index/basic-sop/0.1.0.5/basic-sop.cabal
        ~/my-secure-repo/index/basic-sop/0.1.0.5/package.json
        ~/my-secure-repo/index/generics-sop/0.1.1.1/generics-sop.cabal
        ~/my-secure-repo/index/generics-sop/0.1.1.1/package.json
        ...

    and package the contents of that directory up as the index tarball
    `~/my-secure-repo/00-index.tar.gz`; it will also create the
    top-level metadata files

        ~/my-secure-repo/mirrors.json
        ~/my-secure-repo/root.json
        ~/my-secure-repo/snapshot.json
        ~/my-secure-repo/timestamp.json

4.  The timestamp and snapshot are valid for three days, so you will
    need to resign these files regularly using

        # hackage-repo-tool update \
                            --repo ~/my-secure-repo \
                            --keys ~/my-private-keys

    You can use the same command whenever you add any additional
    packages to your repository.

5.  If you now make this directory available (for instance, by pointing
    Apache httpd at it) you'll be able to use `cabal` to access it remotely by
    defining an appropriate [`repository` stanza](https://www.haskell.org/cabal/users-guide/installing-packages.html#using-secure-repositories):

        repository my-secure-repo
          url: http://packages.example.org/
          secure: True
          root-keys: 2ae741f4c4a5f70ed6e6c48762e0d7a493d8dd265e9cbc6c4037dfc7ceaec70e
                     32d3db5b4403935c0baf52a2bcb05031784a971ee2d43587288776f2e90609db
                     eed36d2bb15f94628221cde558e99c4e1ad36fd243fe3748e1ee7ad00eb9d628
          key-threshold: 2

    Note that the keys in example above must be replaced: You need to
    copy the root key IDs from your generated `root.json` file (or you
    can set `key-threshold` to 0 if you're aware of the security
    implications)
