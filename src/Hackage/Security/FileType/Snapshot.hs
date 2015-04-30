module Hackage.Security.FileType.Snapshot (
    Snapshot(..)
  , MetaInfo(..)
  ) where

import Data.Time

import Hackage.Security.FileType.Common
import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Snapshot = Snapshot {
    snapshotVersion :: Version
  , snapshotExpires :: UTCTime
  , snapshotMeta    :: MetaFiles
  }

instance ToJSON Snapshot where
  toJSON Snapshot{..} = do
    snapshotVersion' <- toJSON snapshotVersion
    snapshotExpires' <- toJSON snapshotExpires
    snapshotMeta'    <- toJSON snapshotMeta
    return $ JSObject [
        ("_type"   , JSString "Snapshot")
      , ("version" , snapshotVersion')
      , ("expires" , snapshotExpires')
      , ("meta"    , snapshotMeta')
      ]

instance FromJSON Snapshot where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    snapshotVersion <- fromJSField enc "version"
    snapshotExpires <- fromJSField enc "expires"
    snapshotMeta    <- fromJSField enc "meta"
    return Snapshot{..}
