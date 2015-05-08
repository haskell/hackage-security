module Hackage.Security.TUF.Timestamp (
    Timestamp(..)
    -- * Accessing trusted information
  , snapshotFileInfo
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.FileMap (FileMap, FileInfo(..))
import Hackage.Security.TUF.Signed
import Hackage.Security.Trusted.Unsafe
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    timestampVersion :: FileVersion
  , timestampExpires :: FileExpires
  , timestampMeta    :: FileMap
  }

instance TUFHeader Timestamp where
  fileVersion = timestampVersion
  fileExpires = timestampExpires

{-------------------------------------------------------------------------------
  Accessing trusted information
-------------------------------------------------------------------------------}

-- | Snapshot file info
--
-- TODO: Perhaps we should change the types to make these runtime errors
-- impossible.
snapshotFileInfo :: Trusted Timestamp -> Trusted FileInfo
snapshotFileInfo (trusted -> Timestamp{..}) =
    DeclareTrusted $ timestampMeta FileMap.! "snapshot.json"

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

instance ReportSchemaErrors m => FromJSON m Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    timestampVersion <- fromJSField enc "version"
    timestampExpires <- fromJSField enc "expires"
    timestampMeta    <- fromJSField enc "meta"
    return Timestamp{..}

instance FromJSON ReadJSON (Signed Timestamp) where
  fromJSON = signedFromJSON
