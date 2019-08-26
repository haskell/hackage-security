{-# LANGUAGE UndecidableInstances #-}
module Hackage.Security.TUF.Snapshot (
    Snapshot(..)
  ) where

import Control.Monad.Except
import Control.Monad.Reader

import Hackage.Security.JSON
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.FileMap
import Hackage.Security.TUF.Layout.Repo
import Hackage.Security.TUF.Signed
import qualified Hackage.Security.TUF.FileMap as FileMap
import Hackage.Security.Util.Pretty (pretty)

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Snapshot = Snapshot {
    snapshotVersion :: FileVersion
  , snapshotExpires :: FileExpires

    -- | File info for the root metadata
    --
    -- We list this explicitly in the snapshot so that we can check if we need
    -- to update the root metadata without first having to download the entire
    -- index tarball.
  , snapshotInfoRoot :: FileInfo

    -- | File info for the mirror metadata
  , snapshotInfoMirrors :: FileInfo

    -- | Compressed index tarball
  , snapshotInfoTarGz :: FileInfo

    -- | Uncompressed index tarball
    --
    -- Repositories are not required to provide this.
  , snapshotInfoTar :: Maybe FileInfo
  }

instance HasHeader Snapshot where
  fileVersion f x = (\y -> x { snapshotVersion = y }) <$> f (snapshotVersion x)
  fileExpires f x = (\y -> x { snapshotExpires = y }) <$> f (snapshotExpires x)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance MonadReader RepoLayout m => ToJSON m Snapshot where
  toJSON Snapshot{..} = do
      repoLayout <- ask
      mkObject [
          ("_type"   , return $ JSString "Snapshot")
        , ("version" , toJSON snapshotVersion)
        , ("expires" , toJSON snapshotExpires)
        , ("meta"    , toJSON (snapshotMeta repoLayout))
        ]
    where
      snapshotMeta repoLayout = FileMap.fromList $ [
          (pathRoot       repoLayout , snapshotInfoRoot)
        , (pathMirrors    repoLayout , snapshotInfoMirrors)
        , (pathIndexTarGz repoLayout , snapshotInfoTarGz)
        ] ++
        [ (pathIndexTar   repoLayout , infoTar) | Just infoTar <- [snapshotInfoTar] ]

instance ( MonadReader RepoLayout m
         , MonadError DeserializationError m
         , ReportSchemaErrors m
         ) => FromJSON m Snapshot where
  fromJSON enc = do
    verifyType enc "Snapshot"
    repoLayout          <- ask
    snapshotVersion     <- fromJSField enc "version"
    snapshotExpires     <- fromJSField enc "expires"
    snapshotMeta        <- fromJSField enc "meta"
    let lookupMeta k = case FileMap.lookup k snapshotMeta of
          Nothing -> expected ("\"" ++ pretty k ++ "\" entry in .meta object") Nothing
          Just v  -> pure v
    snapshotInfoRoot    <- lookupMeta (pathRoot       repoLayout)
    snapshotInfoMirrors <- lookupMeta (pathMirrors    repoLayout)
    snapshotInfoTarGz   <- lookupMeta (pathIndexTarGz repoLayout)
    let snapshotInfoTar = FileMap.lookup (pathIndexTar repoLayout) snapshotMeta
    return Snapshot{..}

instance (MonadKeys m, MonadReader RepoLayout m) => FromJSON m (Signed Snapshot) where
  fromJSON = signedFromJSON

{-------------------------------------------------------------------------------
  Paths used in the snapshot

  NOTE: Since the snapshot lives in the top-level directory of the repository,
  we can safely reinterpret "relative to the repo root" as "relative to the
  snapshot"; hence, this use of 'castRoot' is okay.
-------------------------------------------------------------------------------}

pathRoot, pathMirrors, pathIndexTarGz, pathIndexTar :: RepoLayout -> TargetPath
pathRoot       = TargetPathRepo . repoLayoutRoot
pathMirrors    = TargetPathRepo . repoLayoutMirrors
pathIndexTarGz = TargetPathRepo . repoLayoutIndexTarGz
pathIndexTar   = TargetPathRepo . repoLayoutIndexTar
