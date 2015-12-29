module Hackage.Security.TUF.Layout.Repo (
    -- * Repository layout
    RepoRoot
  , RepoPath
  , RepoLayout(..)
  , hackageRepoLayout
  , cabalLocalRepoLayout
  , anchorRepoPathLocally
  , anchorRepoPathRemotely
  ) where

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
-- 'Web' -- for a repository located at, say, @http://hackage.haskell.org@
-- they happen to coincide, but for one location at
-- @http://example.com/some/subdirectory@ they do not.
data RepoRoot

-- | Paths relative to the root of the repository
type RepoPath = Path RepoRoot

instance Pretty (Path RepoRoot) where
  pretty (Path fp) = "<repo>/" ++ fp

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
    }

-- | The layout used on Hackage
hackageRepoLayout :: RepoLayout
hackageRepoLayout = RepoLayout {
      repoLayoutRoot       = rp $ fragment "root.json"
    , repoLayoutTimestamp  = rp $ fragment "timestamp.json"
    , repoLayoutSnapshot   = rp $ fragment "snapshot.json"
    , repoLayoutMirrors    = rp $ fragment "mirrors.json"
    , repoLayoutIndexTarGz = rp $ fragment "01-index.tar.gz"
    , repoLayoutIndexTar   = rp $ fragment "01-index.tar"
    , repoLayoutPkgTarGz   = \pkgId -> rp $ fragment "package" </> pkgFile pkgId
    }
  where
    pkgFile :: PackageIdentifier -> Path Unrooted
    pkgFile pkgId = fragment (display pkgId) <.> "tar.gz"

    rp :: Path Unrooted -> RepoPath
    rp = rootPath

-- | Layout used by cabal for ("legacy") local repos
--
-- Obviously, such repos do not normally contain any of the TUF files, so their
-- location is more or less arbitrary here.
cabalLocalRepoLayout :: RepoLayout
cabalLocalRepoLayout = hackageRepoLayout {
      repoLayoutPkgTarGz = \pkgId -> rp $ pkgLoc pkgId </> pkgFile pkgId
    }
  where
    pkgLoc :: PackageIdentifier -> Path Unrooted
    pkgLoc pkgId = joinFragments [
          display (packageName    pkgId)
        , display (packageVersion pkgId)
        ]

    pkgFile :: PackageIdentifier -> Path Unrooted
    pkgFile pkgId = fragment (display pkgId) <.> "tar.gz"

    rp :: Path Unrooted -> RepoPath
    rp = rootPath

anchorRepoPathLocally :: FsRoot root => Path root -> RepoPath -> Path root
anchorRepoPathLocally localRoot repoPath = localRoot </> unrootPath repoPath

anchorRepoPathRemotely :: Path Web -> RepoPath -> Path Web
anchorRepoPathRemotely remoteRoot repoPath = remoteRoot </> unrootPath repoPath
