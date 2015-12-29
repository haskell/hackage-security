module Hackage.Security.TUF.Layout.Repo (
    -- * Repository layout
    RepoLayout(..)
  , hackageRepoLayout
  , cabalLocalRepoLayout
  ) where

import Distribution.Package
import Distribution.Text

import Hackage.Security.TUF.Paths
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Repository layout
-------------------------------------------------------------------------------}

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
