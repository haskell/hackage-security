module Hackage.Security.FileType.Timestamp (
    Timestamp(..)
    -- * Utility
  , snapshotHash
  ) where

import Data.Time
import qualified Data.Map as Map

import Hackage.Security.FileType.Common
import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    timestampVersion :: Version
  , timestampExpires :: UTCTime
  , timestampMeta    :: MetaFiles
  }

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Get the hash of the snapshot.json file stored in the timestamp file
--
-- TODO: Perhaps we should change the types to make these runtime errors
-- impossible.
snapshotHash :: Timestamp -> String
snapshotHash Timestamp{..} =
    metaInfoHashes Map.! HashFnSHA256
  where
    Just MetaInfo{..} = lookupMetaFile "snapshot.json" timestampMeta

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Timestamp where
  toJSON Timestamp{..} = do
    timestampVersion' <- toJSON timestampVersion
    timestampExpires' <- toJSON timestampExpires
    timestampMeta'    <- toJSON timestampMeta
    return $ JSObject [
        ("_type"   , JSString "Timestamp")
      , ("version" , timestampVersion')
      , ("expires" , timestampExpires')
      , ("meta"    , timestampMeta')
      ]

instance FromJSON Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    timestampVersion <- fromJSField enc "version"
    timestampExpires <- fromJSField enc "expires"
    timestampMeta    <- fromJSField enc "meta"
    return Timestamp{..}
