-- | Paths used in the TUF data structures
module Hackage.Security.TUF.Paths (
    -- * Repository
    RepoRoot
  , RepoPath
  , anchorRepoPathLocally
  , anchorRepoPathRemotely
    -- * Index
  , IndexRoot
  , IndexPath
    -- * Cache
  , CacheRoot
  , CachePath
  , anchorCachePath
  ) where

import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Repo
-------------------------------------------------------------------------------}

-- | The root of the repository
--
-- Repository roots can be anchored at a remote URL or a local directory.
--
-- Note that even for remote repos 'RepoRoot' is (potentially) different from
-- 'Web' -- for a repository located at, say, @http://hackage.haskell.org@
-- they happen to coincide, but for one location at
-- @http://example.com/some/subdirectory@ they do not.
data RepoRoot

-- | Paths relative to the root of the repository
type RepoPath = Path RepoRoot

instance Pretty (Path RepoRoot) where
  pretty (Path fp) = "<repo>/" ++ fp

anchorRepoPathLocally :: Path root -> RepoPath -> Path root
anchorRepoPathLocally localRoot repoPath = localRoot </> unrootPath repoPath

anchorRepoPathRemotely :: Path Web -> RepoPath -> Path Web
anchorRepoPathRemotely remoteRoot repoPath = remoteRoot </> unrootPath repoPath

{-------------------------------------------------------------------------------
  Index
-------------------------------------------------------------------------------}

-- | The root of the index tarball
data IndexRoot

-- | Paths relative to the root of the index tarball
type IndexPath = Path IndexRoot

instance Pretty (Path IndexRoot) where
    pretty (Path fp) = "<index>/" ++ fp

{-------------------------------------------------------------------------------
  Cache
-------------------------------------------------------------------------------}

-- | The cache directory
data CacheRoot
type CachePath = Path CacheRoot

instance Pretty (Path CacheRoot) where
    pretty (Path fp) = "<cache>/" ++ fp

-- | Anchor a cache path to the location of the cache
anchorCachePath :: Path root -> CachePath -> Path root
anchorCachePath cacheRoot cachePath = cacheRoot </> unrootPath cachePath
