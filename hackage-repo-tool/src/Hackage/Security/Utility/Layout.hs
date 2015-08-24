-- | Layout of the local repository as managed by this tool
--
-- The local repository follows a RepoLayout exactly, but adds some additional
-- files. In addition, we also manage a directory of keys (although this will
-- eventually need to be replaced with a proper key management system).
module Hackage.Security.Utility.Layout (
    -- * File system locations
    RepoLoc(..)
  , KeysLoc(..)
    -- * Additional paths in the repository
  , repoLayoutIndexDir
    -- * Layout of the keys directory
  , KeyRoot
  , KeyPath
  , KeysLayout(..)
  , defaultKeysLayout
  , keysLayoutKey
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

{-------------------------------------------------------------------------------
  File system locations
-------------------------------------------------------------------------------}

newtype RepoLoc = RepoLoc { repoLocPath :: AbsolutePath }
  deriving Eq

newtype KeysLoc = KeysLoc { keysLocPath :: AbsolutePath }
  deriving Eq

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
-- Specifies the directories containing the keys (relative to the keys loc),
-- as well as the filename for individual keys.
data KeysLayout = KeysLayout {
      keysLayoutRoot      :: KeyPath
    , keysLayoutTarget    :: KeyPath
    , keysLayoutTimestamp :: KeyPath
    , keysLayoutSnapshot  :: KeyPath
    , keysLayoutMirrors   :: KeyPath
    , keysLayoutKeyFile   :: Some Key -> UnrootedPath
    }

defaultKeysLayout :: KeysLayout
defaultKeysLayout = KeysLayout {
      keysLayoutRoot      = rp $ fragment' "root"
    , keysLayoutTarget    = rp $ fragment' "target"
    , keysLayoutTimestamp = rp $ fragment' "timestamp"
    , keysLayoutSnapshot  = rp $ fragment' "snapshot"
    , keysLayoutMirrors   = rp $ fragment' "mirrors"
    , keysLayoutKeyFile   = \key -> let kId = keyIdString (someKeyId key)
                                    in fragment' kId <.> "private"
    }
  where
    rp :: UnrootedPath -> KeyPath
    rp = rootPath Rooted

keysLayoutKey :: (KeysLayout -> KeyPath) -> Some Key -> KeysLayout -> KeyPath
keysLayoutKey dir key keysLayout@KeysLayout{..} =
   dir keysLayout </> keysLayoutKeyFile key

{-------------------------------------------------------------------------------
  TargetPath'
-------------------------------------------------------------------------------}

-- | This is a variation on 'TargetPath' parameterized by layout
data TargetPath' =
    InRep    (RepoLayout  -> RepoPath)
  | InIdx    (IndexLayout -> IndexPath)
  | InRepPkg (RepoLayout  -> PackageIdentifier -> RepoPath)  PackageIdentifier
  | InIdxPkg (IndexLayout -> PackageIdentifier -> IndexPath) PackageIdentifier

prettyTargetPath' :: RepoLayout -> TargetPath' -> String
prettyTargetPath' repoLayout = pretty . applyTargetPath' repoLayout

-- | Apply the layout
applyTargetPath' :: RepoLayout -> TargetPath' -> TargetPath
applyTargetPath' repoLayout targetPath =
    case targetPath of
      InRep    file       -> TargetPathRepo  $ file repoLayout
      InIdx    file       -> TargetPathIndex $ file indexLayout
      InRepPkg file pkgId -> TargetPathRepo  $ file repoLayout  pkgId
      InIdxPkg file pkgId -> TargetPathIndex $ file indexLayout pkgId
  where
    indexLayout = repoIndexLayout repoLayout

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Anchor a tarball path to the repo (see 'repoLayoutIndex')
anchorIndexPath :: RepoLayout -> RepoLoc -> (IndexLayout -> IndexPath) -> AbsolutePath
anchorIndexPath repoLayout repoLoc file =
        anchorRepoPath repoLayout repoLoc repoLayoutIndexDir
    </> unrootPath' (file $ repoIndexLayout repoLayout)

anchorRepoPath :: RepoLayout -> RepoLoc -> (RepoLayout -> RepoPath) -> AbsolutePath
anchorRepoPath repoLayout (RepoLoc repoLoc) file =
    anchorRepoPathLocally repoLoc $ file repoLayout

anchorKeyPath :: KeysLayout -> KeysLoc -> (KeysLayout -> KeyPath) -> AbsolutePath
anchorKeyPath keysLayout (KeysLoc keysLoc) dir =
    keysLoc </> unrootPath' (dir keysLayout)

anchorTargetPath' :: RepoLayout -> RepoLoc -> TargetPath' -> AbsolutePath
anchorTargetPath' repoLayout repoLoc = go
  where
    go :: TargetPath' -> AbsolutePath
    go (InRep    file)       = anchorRepoPath  repoLayout repoLoc file
    go (InIdx    file)       = anchorIndexPath repoLayout repoLoc file
    go (InRepPkg file pkgId) = anchorRepoPath  repoLayout repoLoc (`file` pkgId)
    go (InIdxPkg file pkgId) = anchorIndexPath repoLayout repoLoc (`file` pkgId)
