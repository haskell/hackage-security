module Hackage.Security.TUF.Layout (
    -- * Repository layout
    RepoRoot
  , RepoPath
  , RepoLayout(..)
  , repoLayoutPkg
  , hackageRepoLayout
  , anchorRepoPathLocally
  , anchorRepoPathRemotely
    -- * Index tarball layout
  , IndexLayout(..)
  , hackageIndexLayout
    -- * Cache layout
  , CacheRoot
  , CachePath
  , CacheLayout(..)
  , cabalCacheLayout
  , anchorCachePath
  ) where

import Distribution.Package
import Distribution.Text

import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Repository layout
-------------------------------------------------------------------------------}

-- | The root of the repository
--
-- Repository roots can be anchored at a remote URL or a local directory.
--
-- Note that even for remote repos 'RepoRoot' is (potentially) different from
-- 'WebRoot' -- for a repository located at, say, @http://hackage.haskell.org@
-- they happen to coincide, but for one location at
-- @http://example.com/some/subdirectory@ they do not.
data RepoRoot

-- | Paths relative to the root of the repository
type RepoPath = Path (Rooted RepoRoot)

instance Show (Rooted RepoRoot) where show _ = "<repo>"

-- | Directory where a package tarball is stored
data PkgRoot

-- | Paths relative to a package root
type RelativePkgPath = Path (Rooted PkgRoot)

-- | Layout of a repository
data RepoLayout = RepoLayout {
      -- | TUF root metadata
      repoLayoutRoot :: RepoPath

      -- | TUF timestamp
    , repoLayoutTimestamp :: RepoPath

      -- | TUF snapshot
    , repoLayoutSnapshot :: RepoPath

      -- | TUF mirrors list
    , repoLayoutMirrors :: RepoPath

      -- | Compressed index tarball
    , repoLayoutIndexTarGz :: RepoPath

      -- | Uncompressed index tarball
    , repoLayoutIndexTar :: RepoPath

      -- | Path to the package tarball
      --
      -- For package @Foo-1.0@ this might @/package/Foo/1.0@
    , repoLayoutPkgLoc :: PackageIdentifier -> RepoPath

      -- | Filename of the package tarball itself
      --
      -- (relative to 'repoLayoutPkgLoc')
      --
      -- For package @Foo-1.0@ this might be @Foo-1.0.tar.gz@
    , repoLayoutPkgFile :: PackageIdentifier -> RelativePkgPath

      -- | Layout of the index
      --
      -- Since the repository hosts the index, the layout of the index is
      -- not independent of the layout of the repository.
    , repoIndexLayout :: IndexLayout
    }

repoLayoutPkg :: RepoLayout -> PackageIdentifier -> RepoPath
repoLayoutPkg RepoLayout{..} pkgId =
    repoLayoutPkgLoc pkgId </> unrootPath' (repoLayoutPkgFile pkgId)

-- | The layout used on Hackage
hackageRepoLayout :: RepoLayout
hackageRepoLayout = RepoLayout {
      repoLayoutRoot       = rp $ fragment "root.json"
    , repoLayoutTimestamp  = rp $ fragment "timestamp.json"
    , repoLayoutSnapshot   = rp $ fragment "snapshot.json"
    , repoLayoutMirrors    = rp $ fragment "mirrors.json"
    , repoLayoutIndexTarGz = rp $ fragment "00-index.tar.gz"
    , repoLayoutIndexTar   = rp $ fragment "00-index.tar"
    , repoLayoutPkgLoc     = rp  . pkgLoc
    , repoLayoutPkgFile    = rp' . pkgFile
    , repoIndexLayout      = hackageIndexLayout
    }
  where
    rp :: UnrootedPath -> RepoPath
    rp = rootPath Rooted

    rp' :: UnrootedPath -> RelativePkgPath
    rp' = rootPath Rooted

anchorRepoPathLocally :: IsFileSystemRoot root
                      => Path (Rooted root) -> RepoPath -> Path (Rooted root)
anchorRepoPathLocally localRoot repoPath = localRoot </> unrootPath' repoPath

anchorRepoPathRemotely :: URIPath -> RepoPath -> URIPath
anchorRepoPathRemotely remoteRoot repoPath = remoteRoot </> unrootPath' repoPath

{-------------------------------------------------------------------------------
  Index layout
-------------------------------------------------------------------------------}

-- | Layout of the files within the index tarball
data IndexLayout = IndexLayout  {
      -- | TUF metadata for a package
      indexLayoutPkgMetadata :: PackageIdentifier -> TarballPath

      -- | Package .cabal file
    , indexLayoutPkgCabal :: PackageIdentifier -> TarballPath
    }

-- | The layout of the index as maintained on Hackage
hackageIndexLayout :: IndexLayout
hackageIndexLayout = IndexLayout {
      indexLayoutPkgMetadata = \pkgId -> rp $ pkgLoc pkgId </> pkgMetadata pkgId
    , indexLayoutPkgCabal    = \pkgId -> rp $ pkgLoc pkgId </> pkgCabal    pkgId
    }
  where
    rp :: UnrootedPath -> TarballPath
    rp = rootPath Rooted

{-------------------------------------------------------------------------------
  Cache layout
-------------------------------------------------------------------------------}

-- | The cache directory
data CacheRoot
type CachePath = Path (Rooted CacheRoot)

instance Show (Rooted CacheRoot) where show _ = "<cache>"

-- | Location of the various files we cache
--
-- Although the generic TUF algorithms do not care how we organize the cache,
-- we nonetheless specity this here because as long as there are tools which
-- access files in the cache directly we need to define the cache layout.
-- See also comments for 'defaultCacheLayout'.
data CacheLayout = CacheLayout {
    -- | TUF root metadata
    cacheLayoutRoot :: CachePath

    -- | TUF timestamp
  , cacheLayoutTimestamp :: CachePath

    -- | TUF snapshot
  , cacheLayoutSnapshot :: CachePath

    -- | TUF mirrors list
  , cacheLayoutMirrors :: CachePath

    -- | Uncompressed index tarball
  , cacheLayoutIndexTar :: CachePath

    -- | Index to the uncompressed index tarball
  , cacheLayoutIndexIdx :: CachePath
  }

-- | The cache layout cabal-install uses
--
-- We cache the index as @<cache>/00-index.tar@; this is important because
-- `cabal-install` expects to find it there (and does not currently go through
-- the hackage-security library to get files from the index).
cabalCacheLayout :: CacheLayout
cabalCacheLayout = CacheLayout {
      cacheLayoutRoot      = rp $ fragment "root.json"
    , cacheLayoutTimestamp = rp $ fragment "timestamp.json"
    , cacheLayoutSnapshot  = rp $ fragment "snapshot.json"
    , cacheLayoutMirrors   = rp $ fragment "mirrors.json"
    , cacheLayoutIndexTar  = rp $ fragment "00-index.tar"
    , cacheLayoutIndexIdx  = rp $ fragment "00-index.tar.idx"
    }
  where
    rp :: UnrootedPath -> CachePath
    rp = rootPath Rooted

-- | Anchor a cache path to the location of the cache
anchorCachePath :: IsFileSystemRoot root
                => Path (Rooted root) -> CachePath -> Path (Rooted root)
anchorCachePath cacheRoot cachePath = cacheRoot </> unrootPath' cachePath

{-------------------------------------------------------------------------------
  Internal auxiliary
-------------------------------------------------------------------------------}

pkgLoc :: PackageIdentifier -> UnrootedPath
pkgLoc pkgId = joinFragments [
      display (packageName    pkgId)
    , display (packageVersion pkgId)
    ]

pkgFile, pkgCabal, pkgMetadata :: PackageIdentifier -> UnrootedPath
pkgFile      pkgId = fragment (display              pkgId)  <.> "tar.gz"
pkgCabal     pkgId = fragment (display (packageName pkgId)) <.> "cabal"
pkgMetadata _pkgId = fragment "targets"                     <.> "json"
