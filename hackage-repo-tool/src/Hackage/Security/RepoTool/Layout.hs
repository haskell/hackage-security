-- | Layout of the local repository as managed by this tool
--
-- The local repository follows a RepoLayout exactly, but adds some additional
-- files. In addition, we also manage a directory of keys (although this will
-- eventually need to be replaced with a proper key management system).
module Hackage.Security.RepoTool.Layout (
    -- * Additional paths in the repository
    repoLayoutIndexDir
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

import Hackage.Security.RepoTool.Layout.Keys
import Hackage.Security.RepoTool.Options
import Hackage.Security.RepoTool.Paths

{-------------------------------------------------------------------------------
  Additional paths specifically to the kind of repository this tool manages
-------------------------------------------------------------------------------}

-- | Directory containing the unpacked index
--
-- Since the layout of the tarball may not match the layout of the index,
-- we create a local directory with the unpacked contents of the index.
repoLayoutIndexDir :: RepoLayout -> RepoPath
repoLayoutIndexDir _ = rootPath $ fragment "index"

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
      InIdx    file       -> TargetPathIndex $ file globalIndexLayout
      InRepPkg file pkgId -> TargetPathRepo  $ file globalRepoLayout  pkgId
      InIdxPkg file pkgId -> TargetPathIndex $ file globalIndexLayout pkgId

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Anchor a tarball path to the repo (see 'repoLayoutIndex')
anchorIndexPath :: GlobalOpts -> RepoLoc -> (IndexLayout -> IndexPath) -> Path Absolute
anchorIndexPath opts@GlobalOpts{..} repoLoc file =
        anchorRepoPath opts repoLoc repoLayoutIndexDir
    </> unrootPath (file globalIndexLayout)

anchorRepoPath :: GlobalOpts -> RepoLoc -> (RepoLayout -> RepoPath) -> Path Absolute
anchorRepoPath GlobalOpts{..} (RepoLoc repoLoc) file =
    anchorRepoPathLocally repoLoc $ file globalRepoLayout

anchorKeyPath :: GlobalOpts -> KeysLoc -> (KeysLayout -> KeyPath) -> Path Absolute
anchorKeyPath GlobalOpts{..} (KeysLoc keysLoc) dir =
    keysLoc </> unrootPath (dir globalKeysLayout)

anchorTargetPath' :: GlobalOpts -> RepoLoc -> TargetPath' -> Path Absolute
anchorTargetPath' opts repoLoc = go
  where
    go :: TargetPath' -> Path Absolute
    go (InRep    file)       = anchorRepoPath  opts repoLoc file
    go (InIdx    file)       = anchorIndexPath opts repoLoc file
    go (InRepPkg file pkgId) = anchorRepoPath  opts repoLoc (`file` pkgId)
    go (InIdxPkg file pkgId) = anchorIndexPath opts repoLoc (`file` pkgId)
