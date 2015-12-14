module Hackage.Security.TUF.Layout (
    -- * Repository layout
    RepoRoot
  , RepoPath
  , RepoLayout(..)
  , hackageRepoLayout
  , cabalLocalRepoLayout
  , anchorRepoPathLocally
  , anchorRepoPathRemotely
    -- * Index tarball layout
  , IndexRoot
  , IndexPath
  , IndexLayout(..)
  , IndexFile(..)
  , hackageIndexLayout
    -- * Cache layout
  , CacheRoot
  , CachePath
  , CacheLayout(..)
  , cabalCacheLayout
  , anchorCachePath
  ) where

import qualified System.FilePath as FP

import Distribution.Package
import Distribution.Text

import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

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

instance IsRoot RepoRoot where showRoot _ = "<repo>"

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
    , repoLayoutPkgTarGz :: PackageIdentifier -> RepoPath

      -- | Layout of the index
      --
      -- Since the repository hosts the index, the layout of the index is
      -- not independent of the layout of the repository.
    , repoIndexLayout :: IndexLayout
    }

-- | The layout used on Hackage
hackageRepoLayout :: RepoLayout
hackageRepoLayout = RepoLayout {
      repoLayoutRoot       = rp $ fragment' "root.json"
    , repoLayoutTimestamp  = rp $ fragment' "timestamp.json"
    , repoLayoutSnapshot   = rp $ fragment' "snapshot.json"
    , repoLayoutMirrors    = rp $ fragment' "mirrors.json"
    , repoLayoutIndexTarGz = rp $ fragment' "01-index.tar.gz"
    , repoLayoutIndexTar   = rp $ fragment' "01-index.tar"
    , repoLayoutPkgTarGz   = \pkgId -> rp $ fragment' "package" </> pkgFile pkgId
    , repoIndexLayout      = hackageIndexLayout
    }
  where
    pkgFile :: PackageIdentifier -> UnrootedPath
    pkgFile pkgId = fragment' (display pkgId) <.> "tar.gz"

    rp :: UnrootedPath -> RepoPath
    rp = rootPath Rooted

-- | Layout used by cabal for ("legacy") local repos
--
-- Obviously, such repos do not normally contain any of the TUF files, so their
-- location is more or less arbitrary here.
cabalLocalRepoLayout :: RepoLayout
cabalLocalRepoLayout = hackageRepoLayout {
      repoLayoutPkgTarGz = \pkgId -> rp $ pkgLoc pkgId </> pkgFile pkgId
    }
  where
    pkgLoc :: PackageIdentifier -> UnrootedPath
    pkgLoc pkgId = joinFragments [
          mkFragment $ display (packageName    pkgId)
        , mkFragment $ display (packageVersion pkgId)
        ]

    pkgFile :: PackageIdentifier -> UnrootedPath
    pkgFile pkgId = fragment' (display pkgId) <.> "tar.gz"

    rp :: UnrootedPath -> RepoPath
    rp = rootPath Rooted

anchorRepoPathLocally :: IsFileSystemRoot root
                      => Path (Rooted root) -> RepoPath -> Path (Rooted root)
anchorRepoPathLocally localRoot repoPath = localRoot </> unrootPath' repoPath

anchorRepoPathRemotely :: URIPath -> RepoPath -> URIPath
anchorRepoPathRemotely remoteRoot repoPath = remoteRoot </> unrootPath' repoPath

{-------------------------------------------------------------------------------
  Index layout
-------------------------------------------------------------------------------}

-- | The root of the index tarball
data IndexRoot

-- | Paths relative to the root of the index tarball
type IndexPath = Path (Rooted RepoRoot)

instance IsRoot IndexRoot where showRoot _ = "<index>"

-- | Layout of the files within the index tarball
data IndexLayout = IndexLayout  {
      -- | Translate an 'IndexFile' to a path
      indexFileToPath :: IndexFile -> IndexPath

      -- | Parse an 'FilePath'
      --
      -- TODO: This takes a 'FilePath' rather than an 'IndexPath' for now,
      -- because we need this to be relatively quick and the the indirection
      -- through 'IndexPath' doesn't really gain us anything here.
    , indexFileFromPath :: FilePath -> Maybe IndexFile
    }

-- | Files that we might request from the index
--
-- TODO: If we wanted to support legacy Hackage, we should also have a case for
-- the global preferred-versions file. But supporting legacy Hackage will
-- probably require more work anyway..
data IndexFile =
    -- | Package-specific metadata (@targets.json@)
    IndexPkgMetadata PackageIdentifier

    -- | Cabal file for a package
  | IndexPkgCabal PackageIdentifier

    -- | Preferred versions a package
  | IndexPkgPrefs PackageName
  deriving Show

instance Pretty IndexFile where
  pretty (IndexPkgMetadata pkgId) = "metadata for " ++ display pkgId
  pretty (IndexPkgCabal    pkgId) = ".cabal for " ++ display pkgId
  pretty (IndexPkgPrefs    pkgNm) = "preferred-versions for " ++ display pkgNm

-- | The layout of the index as maintained on Hackage
hackageIndexLayout :: IndexLayout
hackageIndexLayout = IndexLayout {
      indexFileToPath   = toPath
    , indexFileFromPath = fromPath
    }
  where
    toPath :: IndexFile -> IndexPath
    toPath (IndexPkgMetadata pkgId) = fromFragments [
                                          display (packageName    pkgId)
                                        , display (packageVersion pkgId)
                                        , display (packageName pkgId) ++ ".cabal"
                                        ]
    toPath (IndexPkgCabal    pkgId) = fromFragments [
                                          display (packageName    pkgId)
                                        , display (packageVersion pkgId)
                                        , "package.json"
                                        ]
    toPath (IndexPkgPrefs    pkgNm) = fromFragments [
                                          display pkgNm
                                        , "preferred-versions"
                                        ]

    fromFragments :: [String] -> IndexPath
    fromFragments = rootPath Rooted . joinFragments . map mkFragment

    fromPath :: FilePath -> Maybe IndexFile
    fromPath fp = case FP.splitPath fp of
      [pkg, version, file] -> do
        pkgId <- simpleParse (init pkg ++ "-" ++ init version)
        case FP.takeExtension file of
          ".cabal"   -> return $ IndexPkgCabal    pkgId
          ".json"    -> return $ IndexPkgMetadata pkgId
          _otherwise -> Nothing
      [pkg, "preferred-versions"] ->
        IndexPkgPrefs <$> simpleParse (init pkg)
      _otherwise -> Nothing

{-------------------------------------------------------------------------------
  Cache layout
-------------------------------------------------------------------------------}

-- | The cache directory
data CacheRoot
type CachePath = Path (Rooted CacheRoot)

instance IsRoot CacheRoot where showRoot _ = "<cache>"

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

    -- | Compressed index tarball
    --
    -- We cache both the compressed and the uncompressed tarballs, because
    -- incremental updates happen through the compressed tarball, but reads
    -- happen through the uncompressed one (with the help of the tarball index).
  , cacheLayoutIndexTarGz :: CachePath
  }

-- | The cache layout cabal-install uses
--
-- We cache the index as @<cache>/00-index.tar@; this is important because
-- `cabal-install` expects to find it there (and does not currently go through
-- the hackage-security library to get files from the index).
cabalCacheLayout :: CacheLayout
cabalCacheLayout = CacheLayout {
      cacheLayoutRoot       = rp $ fragment' "root.json"
    , cacheLayoutTimestamp  = rp $ fragment' "timestamp.json"
    , cacheLayoutSnapshot   = rp $ fragment' "snapshot.json"
    , cacheLayoutMirrors    = rp $ fragment' "mirrors.json"
    , cacheLayoutIndexTar   = rp $ fragment' "00-index.tar"
    , cacheLayoutIndexIdx   = rp $ fragment' "00-index.tar.idx"
    , cacheLayoutIndexTarGz = rp $ fragment' "00-index.tar.gz"
    }
  where
    rp :: UnrootedPath -> CachePath
    rp = rootPath Rooted

-- | Anchor a cache path to the location of the cache
anchorCachePath :: IsFileSystemRoot root
                => Path (Rooted root) -> CachePath -> Path (Rooted root)
anchorCachePath cacheRoot cachePath = cacheRoot </> unrootPath' cachePath
