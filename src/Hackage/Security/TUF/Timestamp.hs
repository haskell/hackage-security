module Hackage.Security.TUF.Timestamp (
    Timestamp(..)
    -- * Accessing trusted information
  , trustedTimestampInfoSnapshot
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Signed
import Hackage.Security.Trusted.Unsafe
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    timestampVersion      :: FileVersion
  , timestampExpires      :: FileExpires
  , timestampInfoSnapshot :: FileInfo
  }

instance TUFHeader Timestamp where
  fileVersion = timestampVersion
  fileExpires = Just . timestampExpires
  describeFile _ = "timestamp"

{-------------------------------------------------------------------------------
  Accessing trusted information
-------------------------------------------------------------------------------}

-- | Snapshot file info
trustedTimestampInfoSnapshot :: Trusted Timestamp -> Trusted FileInfo
trustedTimestampInfoSnapshot = DeclareTrusted . timestampInfoSnapshot . trusted

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Timestamp where
  toJSON Timestamp{..} = JSObject [
        ("_type"   , JSString "Timestamp")
      , ("version" , toJSON timestampVersion)
      , ("expires" , toJSON timestampExpires)
      , ("meta"    , toJSON timestampMeta)
      ]
    where
      timestampMeta = FileMap.fromList [
          ("snapshot.json", timestampInfoSnapshot)
        ]

instance ReportSchemaErrors m => FromJSON m Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    timestampVersion      <- fromJSField enc "version"
    timestampExpires      <- fromJSField enc "expires"
    timestampMeta         <- fromJSField enc "meta"
    timestampInfoSnapshot <- FileMap.lookupM timestampMeta "snapshot.json"
    return Timestamp{..}

instance FromJSON ReadJSON (Signed Timestamp) where
  fromJSON = signedFromJSON
