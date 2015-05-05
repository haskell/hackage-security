module Hackage.Security.TUF.Timestamp (
    Timestamp(..)
    -- * Utility
  , snapshotHash
  ) where

import Data.Time
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.TUF.FileMap (FileMap, FileInfo(..), HashFn(..))
import Hackage.Security.TUF.Ints
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Timestamp = Timestamp {
    timestampVersion :: Version
  , timestampExpires :: UTCTime
  , timestampMeta    :: FileMap
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
    fileInfoHashes Map.! HashFnSHA256
  where
    Just FileInfo{..} = FileMap.lookup "snapshot.json" timestampMeta

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m Timestamp where
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

instance ReportSchemaErrors m => FromJSON m Timestamp where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    timestampVersion <- fromJSField enc "version"
    timestampExpires <- fromJSField enc "expires"
    timestampMeta    <- fromJSField enc "meta"
    return Timestamp{..}
