module Hackage.Security.TUF.Layout.Cache (
    -- * Cache layout
    CacheRoot
  , CachePath
  , CacheLayout(..)
  , cabalCacheLayout
  , anchorCachePath
  ) where

import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Cache layout
-------------------------------------------------------------------------------}

-- | The cache directory
data CacheRoot
type CachePath = Path CacheRoot

instance Pretty (Path CacheRoot) where
    pretty (Path fp) = "<cache>/" ++ fp

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
      cacheLayoutRoot       = rp $ fragment "root.json"
    , cacheLayoutTimestamp  = rp $ fragment "timestamp.json"
    , cacheLayoutSnapshot   = rp $ fragment "snapshot.json"
    , cacheLayoutMirrors    = rp $ fragment "mirrors.json"
    , cacheLayoutIndexTar   = rp $ fragment "00-index.tar"
    , cacheLayoutIndexIdx   = rp $ fragment "00-index.tar.idx"
    , cacheLayoutIndexTarGz = rp $ fragment "00-index.tar.gz"
    }
  where
    rp :: Path Unrooted -> CachePath
    rp = rootPath

-- | Anchor a cache path to the location of the cache
anchorCachePath :: FsRoot root => Path root -> CachePath -> Path root
anchorCachePath cacheRoot cachePath = cacheRoot </> unrootPath cachePath
