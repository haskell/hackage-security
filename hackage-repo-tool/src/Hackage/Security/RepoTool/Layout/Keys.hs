-- | Layout of the directory containing the (private) keys
module Hackage.Security.RepoTool.Layout.Keys (
    -- * Layout of the keys directory
    KeysLayout(..)
  , defaultKeysLayout
  , keysLayoutKey
  ) where

import Hackage.Security.Client
import Hackage.Security.Util.Path
import Hackage.Security.Util.Some

import Hackage.Security.RepoTool.Paths

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
    , keysLayoutKeyFile   :: Some Key -> Path Unrooted
    }

defaultKeysLayout :: KeysLayout
defaultKeysLayout = KeysLayout {
      keysLayoutRoot      = rp $ fragment "root"
    , keysLayoutTarget    = rp $ fragment "target"
    , keysLayoutTimestamp = rp $ fragment "timestamp"
    , keysLayoutSnapshot  = rp $ fragment "snapshot"
    , keysLayoutMirrors   = rp $ fragment "mirrors"
    , keysLayoutKeyFile   = \key -> let kId = keyIdString (someKeyId key)
                                    in fragment kId <.> "private"
    }
  where
    rp :: Path Unrooted -> KeyPath
    rp = rootPath

keysLayoutKey :: (KeysLayout -> KeyPath) -> Some Key -> KeysLayout -> KeyPath
keysLayoutKey dir key keysLayout@KeysLayout{..} =
   dir keysLayout </> keysLayoutKeyFile key
