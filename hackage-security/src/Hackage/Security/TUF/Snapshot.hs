module Hackage.Security.TUF.Snapshot (
    Snapshot(..)
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.Signed
import qualified Hackage.Security.TUF.FileMap as FileMap

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

instance DescribeFile Snapshot where
  describeFile _ = "snapshot"

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
    where
      snapshotMeta = FileMap.fromList $ [
          ("root.json"    , snapshotInfoRoot)
        , ("mirrors.json" , snapshotInfoMirrors)
        , ("index.tar.gz" , snapshotInfoTarGz)
        ] ++
        [ ("index.tar" , infoTar) | Just infoTar <- [snapshotInfoTar] ]

instance ReportSchemaErrors m => FromJSON m Snapshot where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    snapshotVersion     <- fromJSField enc "version"
    snapshotExpires     <- fromJSField enc "expires"
    snapshotMeta        <- fromJSField enc "meta"
    snapshotInfoRoot    <- FileMap.lookupM snapshotMeta "root.json"
    snapshotInfoMirrors <- FileMap.lookupM snapshotMeta "mirrors.json"
    snapshotInfoTarGz   <- FileMap.lookupM snapshotMeta "index.tar.gz"
    let snapshotInfoTar = FileMap.lookup "index.tar" snapshotMeta
    return Snapshot{..}

instance FromJSON ReadJSON (Signed Snapshot) where
  fromJSON = signedFromJSON
