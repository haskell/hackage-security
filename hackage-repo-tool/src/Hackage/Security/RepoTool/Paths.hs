-- | Additional paths
module Hackage.Security.RepoTool.Paths (
    -- * Repo
    RepoLoc(..)
    -- * Keys
  , KeyRoot
  , KeyPath
  , KeysLoc(..)
  ) where

import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Repo
-------------------------------------------------------------------------------}

newtype RepoLoc = RepoLoc { repoLocPath :: Path Absolute }
  deriving Eq

{-------------------------------------------------------------------------------
  Keys
-------------------------------------------------------------------------------}

-- | The key directory
data KeyRoot
type KeyPath = Path KeyRoot

instance Pretty (Path KeyRoot) where
    pretty (Path fp) = "<keys>/" ++ fp

newtype KeysLoc = KeysLoc { keysLocPath :: Path Absolute }
  deriving Eq
