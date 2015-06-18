module Hackage.Security.TUF.Timestamp (
    Timestamp(..)
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Signed
import Hackage.Security.Util.Path
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    timestampVersion      :: FileVersion
  , timestampExpires      :: FileExpires
  , timestampInfoSnapshot :: FileInfo
  }

instance HasHeader Timestamp where
  fileVersion f x = (\y -> x { timestampVersion = y }) <$> f (timestampVersion x)
  fileExpires f x = (\y -> x { timestampExpires = y }) <$> f (timestampExpires x)

instance DescribeFile Timestamp where
  describeFile _ = "timestamp"

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
          (fragment "snapshot.json", timestampInfoSnapshot)
        ]

instance ReportSchemaErrors m => FromJSON m Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    timestampVersion      <- fromJSField enc "version"
    timestampExpires      <- fromJSField enc "expires"
    timestampMeta         <- fromJSField enc "meta"
    timestampInfoSnapshot <- FileMap.lookupM timestampMeta (fragment "snapshot.json")
    return Timestamp{..}

instance FromJSON ReadJSON (Signed Timestamp) where
  fromJSON = signedFromJSON
