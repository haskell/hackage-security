-- | Layout of the local repository as managed by this tool
--
-- The local repository follows a RepoLayout exactly, but adds some additional
-- files. In addition, we also manage a directory of keys (although this will
-- eventually need to be replaced with a proper key management system).
module Hackage.Security.Local.Layout (
    -- * Additional paths
    repoLayoutCabal
  , repoLayoutIndexDir
    -- * Layout of the keys directory
  , KeyRoot
  , KeyPath
  , KeyLayout(..)
  , defaultKeyLayout
  , keyLayoutKey
    -- * Utility
  , anchorIndexPath
  , anchorRepoPath
  , anchorKeyPath
  ) where

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client
import Hackage.Security.Util.Path
import Hackage.Security.Util.Some
import Hackage.Security.Local.Options

{-------------------------------------------------------------------------------
  Additional paths specifically to the kind of repository this tool manages
-------------------------------------------------------------------------------}

-- | Location of the @.cabal@ file
--
-- Repositories don't have to serve the .cabal files directly; cabal will only
-- read them from the index. However, for the purposes of this tool, when we
-- _create_ the index, we expect the .cabal file to exist in the same directory
-- as the package tarball.
repoLayoutCabal :: RepoLayout -> PackageIdentifier -> RepoPath
repoLayoutCabal RepoLayout{..} pkgId = repoLayoutPkgLoc pkgId </> pkgCabal pkgId

-- | Directory containing the unpacked index
--
-- Since the layout of the tarball may not match the layout of the index,
-- we create a local directory with the unpacked contents of the index.
repoLayoutIndexDir :: RepoLayout -> RepoPath
repoLayoutIndexDir _ = rootPath Rooted $ fragment "index"

-- | The name of the .cabal file we expect to find in the local repo
--
-- NOTE: This is not necessarily the same as the name in the index
-- (though it typically will be)
pkgCabal :: PackageIdentifier -> UnrootedPath
pkgCabal pkgId = fragment (display (packageName pkgId)) <.> "cabal"

{-------------------------------------------------------------------------------
  Key layout
-------------------------------------------------------------------------------}

-- | The key directory
data KeyRoot
type KeyPath = Path (Rooted KeyRoot)

instance Show (Rooted KeyRoot) where show _ = "<keys>"

-- | Layout of the keys directory
--
-- Specifies the directories containing the keys (relative to 'globalKeys'),
-- as well as the filename for individual keys.
data KeyLayout = KeyLayout {
      keyLayoutRoot      :: KeyPath
    , keyLayoutTarget    :: KeyPath
    , keyLayoutTimestamp :: KeyPath
    , keyLayoutSnapshot  :: KeyPath
    , keyLayoutMirrors   :: KeyPath
    , keyLayoutKeyFile   :: Some Key -> UnrootedPath
    }

defaultKeyLayout :: KeyLayout
defaultKeyLayout = KeyLayout {
      keyLayoutRoot      = rp $ fragment "root"
    , keyLayoutTarget    = rp $ fragment "target"
    , keyLayoutTimestamp = rp $ fragment "timestamp"
    , keyLayoutSnapshot  = rp $ fragment "snapshot"
    , keyLayoutMirrors   = rp $ fragment "mirrors"
    , keyLayoutKeyFile   = \key -> let kId = keyIdString (someKeyId key)
                                   in fragment kId <.> "private"
    }
  where
    rp :: UnrootedPath -> KeyPath
    rp = rootPath Rooted

keyLayoutKey :: (KeyLayout -> KeyPath) -> Some Key -> KeyLayout -> KeyPath
keyLayoutKey dir key keyLayout@KeyLayout{..} =
   dir keyLayout </> keyLayoutKeyFile key

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Anchor a tarball path to the repo (see 'repoLayoutIndex')
anchorIndexPath :: GlobalOpts -> (IndexLayout -> TarballPath) -> AbsolutePath
anchorIndexPath opts@GlobalOpts{..} file =
        anchorRepoPath opts repoLayoutIndexDir
    </> unrootPath' (file $ repoIndexLayout globalRepoLayout)

anchorRepoPath :: GlobalOpts -> (RepoLayout -> RepoPath) -> AbsolutePath
anchorRepoPath GlobalOpts{..} file =
    anchorRepoPathLocally globalRepo $ file globalRepoLayout

anchorKeyPath :: GlobalOpts -> (KeyLayout -> KeyPath) -> AbsolutePath
anchorKeyPath GlobalOpts{..} dir =
    globalKeys </> unrootPath' (dir defaultKeyLayout)
