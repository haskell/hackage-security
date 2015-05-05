module Hackage.Security.TUF.Snapshot (
    Snapshot(..)
  ) where

import Data.Time

import Hackage.Security.JSON
import Hackage.Security.TUF.FileMap (FileMap)
import Hackage.Security.TUF.Ints

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Snapshot = Snapshot {
    snapshotVersion :: Version
  , snapshotExpires :: UTCTime
  , snapshotMeta    :: FileMap
  }

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m Snapshot where
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

instance ReportSchemaErrors m => FromJSON m Snapshot where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    snapshotVersion <- fromJSField enc "version"
    snapshotExpires <- fromJSField enc "expires"
    snapshotMeta    <- fromJSField enc "meta"
    return Snapshot{..}
