-- | Layout of the local repository as managed by this tool
--
-- The local repository follows a RepoLayout exactly, but adds some additional
-- files. In addition, we also manage a directory of keys (although this will
-- eventually need to be replaced with a proper key management system).
module Hackage.Security.Local.Layout (
    -- * Additional paths
    repoLayoutIndexDir
    -- * Layout of the keys directory
  , KeyRoot
  , KeyPath
  , KeyLayout(..)
  , defaultKeyLayout
  , keyLayoutKey
    -- * Layout-parametrized version of TargetPath
  , TargetPath'(..)
  , prettyTargetPath'
  , applyTargetPath'
    -- * Utility
  , anchorIndexPath
  , anchorRepoPath
  , anchorKeyPath
  , anchorTargetPath'
  ) where

import Distribution.Package

import Hackage.Security.Client
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some
import Hackage.Security.Local.Options

{-------------------------------------------------------------------------------
  Additional paths specifically to the kind of repository this tool manages
-------------------------------------------------------------------------------}

-- | Directory containing the unpacked index
--
-- Since the layout of the tarball may not match the layout of the index,
-- we create a local directory with the unpacked contents of the index.
repoLayoutIndexDir :: RepoLayout -> RepoPath
repoLayoutIndexDir _ = rootPath Rooted $ fragment' "index"

{-------------------------------------------------------------------------------
  Key layout
-------------------------------------------------------------------------------}

-- | The key directory
data KeyRoot
type KeyPath = Path (Rooted KeyRoot)

instance IsRoot KeyRoot where showRoot _ = "<keys>"

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
      keyLayoutRoot      = rp $ fragment' "root"
    , keyLayoutTarget    = rp $ fragment' "target"
    , keyLayoutTimestamp = rp $ fragment' "timestamp"
    , keyLayoutSnapshot  = rp $ fragment' "snapshot"
    , keyLayoutMirrors   = rp $ fragment' "mirrors"
    , keyLayoutKeyFile   = \key -> let kId = keyIdString (someKeyId key)
                                   in fragment' kId <.> "private"
    }
  where
    rp :: UnrootedPath -> KeyPath
    rp = rootPath Rooted

keyLayoutKey :: (KeyLayout -> KeyPath) -> Some Key -> KeyLayout -> KeyPath
keyLayoutKey dir key keyLayout@KeyLayout{..} =
   dir keyLayout </> keyLayoutKeyFile key

{-------------------------------------------------------------------------------
  TargetPath'
-------------------------------------------------------------------------------}

-- | This is a variation on 'TargetPath' parameterized by layout
data TargetPath' =
    InRep    (RepoLayout  -> RepoPath)
  | InIdx    (IndexLayout -> IndexPath)
  | InRepPkg (RepoLayout  -> PackageIdentifier -> RepoPath)  PackageIdentifier
  | InIdxPkg (IndexLayout -> PackageIdentifier -> IndexPath) PackageIdentifier

prettyTargetPath' :: GlobalOpts -> TargetPath' -> String
prettyTargetPath' opts = pretty . applyTargetPath' opts

-- | Apply the layout
applyTargetPath' :: GlobalOpts -> TargetPath' -> TargetPath
applyTargetPath' GlobalOpts{..} targetPath =
    case targetPath of
      InRep    file       -> TargetPathRepo  $ file globalRepoLayout
      InIdx    file       -> TargetPathIndex $ file indexLayout
      InRepPkg file pkgId -> TargetPathRepo  $ file globalRepoLayout pkgId
      InIdxPkg file pkgId -> TargetPathIndex $ file indexLayout      pkgId
  where
    indexLayout = repoIndexLayout globalRepoLayout

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Anchor a tarball path to the repo (see 'repoLayoutIndex')
anchorIndexPath :: GlobalOpts -> (IndexLayout -> IndexPath) -> AbsolutePath
anchorIndexPath opts@GlobalOpts{..} file =
        anchorRepoPath opts repoLayoutIndexDir
    </> unrootPath' (file $ repoIndexLayout globalRepoLayout)

anchorRepoPath :: GlobalOpts -> (RepoLayout -> RepoPath) -> AbsolutePath
anchorRepoPath GlobalOpts{..} file =
    anchorRepoPathLocally globalRepo $ file globalRepoLayout

anchorKeyPath :: GlobalOpts -> (KeyLayout -> KeyPath) -> AbsolutePath
anchorKeyPath GlobalOpts{..} dir =
    globalKeys </> unrootPath' (dir defaultKeyLayout)

anchorTargetPath' :: GlobalOpts -> TargetPath' -> AbsolutePath
anchorTargetPath' opts = go
  where
    go :: TargetPath' -> AbsolutePath
    go (InRep    file)       = anchorRepoPath  opts file
    go (InIdx    file)       = anchorIndexPath opts file
    go (InRepPkg file pkgId) = anchorRepoPath  opts (`file` pkgId)
    go (InIdxPkg file pkgId) = anchorIndexPath opts (`file` pkgId)
