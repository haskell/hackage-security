module Hackage.Security.TUF.Snapshot (
    Snapshot(..)
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.FileMap (FileMap)
import Hackage.Security.TUF.Signed

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Snapshot = Snapshot {
    snapshotVersion :: FileVersion
  , snapshotExpires :: FileExpires
  , snapshotMeta    :: FileMap
  }

instance TUFHeader Snapshot where
  fileVersion = snapshotVersion
  fileExpires = snapshotExpires

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Snapshot where
  toJSON Snapshot{..} = JSObject [
        ("_type"   , JSString "Snapshot")
      , ("version" , toJSON snapshotVersion)
      , ("expires" , toJSON snapshotExpires)
      , ("meta"    , toJSON snapshotMeta)
      ]

instance ReportSchemaErrors m => FromJSON m Snapshot where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    snapshotVersion <- fromJSField enc "version"
    snapshotExpires <- fromJSField enc "expires"
    snapshotMeta    <- fromJSField enc "meta"
    return Snapshot{..}

instance FromJSON ReadJSON (Signed Snapshot) where
  fromJSON = signedFromJSON
