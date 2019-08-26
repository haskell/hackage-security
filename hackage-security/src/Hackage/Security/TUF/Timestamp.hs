{-# LANGUAGE UndecidableInstances #-}
module Hackage.Security.TUF.Timestamp (
    Timestamp(..)
  ) where

import Control.Monad.Except
import Control.Monad.Reader

import Hackage.Security.JSON
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.FileMap
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Layout.Repo
import Hackage.Security.TUF.Signed
import qualified Hackage.Security.TUF.FileMap as FileMap
import Hackage.Security.Util.Pretty (pretty)

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

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance MonadReader RepoLayout m => ToJSON m Timestamp where
  toJSON Timestamp{..} = do
      repoLayout <- ask
      mkObject [
          ("_type"   , return $ JSString "Timestamp")
        , ("version" , toJSON timestampVersion)
        , ("expires" , toJSON timestampExpires)
        , ("meta"    , toJSON (timestampMeta repoLayout))
        ]
    where
      timestampMeta repoLayout = FileMap.fromList [
          (pathSnapshot repoLayout, timestampInfoSnapshot)
        ]

instance ( MonadReader RepoLayout m
         , MonadError DeserializationError m
         , ReportSchemaErrors m
         ) => FromJSON m Timestamp where
  fromJSON enc = do
    verifyType enc "Timestamp"
    repoLayout            <- ask
    timestampVersion      <- fromJSField enc "version"
    timestampExpires      <- fromJSField enc "expires"
    timestampMeta         <- fromJSField enc "meta"
    let lookupMeta k = case FileMap.lookup k timestampMeta of
          Nothing -> expected ("\"" ++ pretty k ++ "\" entry in .meta object") Nothing
          Just v  -> pure v
    timestampInfoSnapshot <- lookupMeta (pathSnapshot repoLayout)
    return Timestamp{..}

instance (MonadKeys m, MonadReader RepoLayout m) => FromJSON m (Signed Timestamp) where
  fromJSON = signedFromJSON

{-------------------------------------------------------------------------------
  Paths used in the timestamp

  NOTE: Since the timestamp lives in the top-level directory of the repository,
  we can safely reinterpret "relative to the repo root" as "relative to the
  timestamp"; hence, this use of 'castRoot' is okay.
-------------------------------------------------------------------------------}

pathSnapshot :: RepoLayout -> TargetPath
pathSnapshot = TargetPathRepo . repoLayoutSnapshot
