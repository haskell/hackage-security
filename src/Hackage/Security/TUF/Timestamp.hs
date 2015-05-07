module Hackage.Security.TUF.Timestamp (
    Timestamp(Timestamp)
  , _timestampVersion
  , _timestampExpires
    -- * Accessing verified information
  , timestampMeta
  , snapshotHash
  ) where

import Data.Time
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.FileMap (FileMap, FileInfo(..), HashFn(..))
import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.Signed
import qualified Hackage.Security.TUF.FileMap as FileMap
import {-# SOURCE #-} Hackage.Security.Verified

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    _timestampVersion :: FileVersion
  , _timestampExpires :: UTCTime
  , _timestampMeta    :: FileMap
  }

{-------------------------------------------------------------------------------
  Accessors
-------------------------------------------------------------------------------}

timestampMeta :: Verified Timestamp -> FileMap
timestampMeta = _timestampMeta . verified

-- | Get the hash of the snapshot.json file stored in the timestamp file
--
-- TODO: Perhaps we should change the types to make these runtime errors
-- impossible.
snapshotHash :: Verified Timestamp -> String
snapshotHash ts =
    fileInfoHashes Map.! HashFnSHA256
  where
    Just FileInfo{..} = FileMap.lookup "snapshot.json" (timestampMeta ts)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Timestamp where
  toJSON Timestamp{..} = JSObject [
        ("_type"   , JSString "Timestamp")
      , ("version" , toJSON _timestampVersion)
      , ("expires" , toJSON _timestampExpires)
      , ("meta"    , toJSON _timestampMeta)
      ]

instance ReportSchemaErrors m => FromJSON m Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    _timestampVersion <- fromJSField enc "version"
    _timestampExpires <- fromJSField enc "expires"
    _timestampMeta    <- fromJSField enc "meta"
    return Timestamp{..}

instance FromJSON ReadJSON (Signed Timestamp) where
  fromJSON = signedFromJSON
