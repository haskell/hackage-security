module Hackage.Security.TUF.Snapshot (
    Snapshot(..)
    -- * Trusted info
  , trustedSnapshotInfoRoot
  , trustedSnapshotInfoTar
  , trustedSnapshotInfoTarGz
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.Signed
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Snapshot = Snapshot {
    snapshotVersion   :: FileVersion
  , snapshotExpires   :: FileExpires
  , snapshotInfoRoot  :: FileInfo
  , snapshotInfoTar   :: FileInfo
  , snapshotInfoTarGz :: FileInfo
  }

instance TUFHeader Snapshot where
  fileVersion = snapshotVersion
  fileExpires = snapshotExpires

{-------------------------------------------------------------------------------
  Extracting trusted information
-------------------------------------------------------------------------------}

trustedSnapshotInfoRoot  :: Trusted Snapshot -> Trusted FileInfo
trustedSnapshotInfoRoot = DeclareTrusted . snapshotInfoRoot . trusted

trustedSnapshotInfoTar :: Trusted Snapshot -> Trusted FileInfo
trustedSnapshotInfoTar = DeclareTrusted . snapshotInfoTar . trusted

trustedSnapshotInfoTarGz :: Trusted Snapshot -> Trusted FileInfo
trustedSnapshotInfoTarGz = DeclareTrusted . snapshotInfoTarGz . trusted

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
      snapshotMeta = FileMap.fromList [
          ("root.json"    , snapshotInfoRoot)
        , ("index.tar"    , snapshotInfoTar)
        , ("index.tar.gz" , snapshotInfoTarGz)
        ]

instance ReportSchemaErrors m => FromJSON m Snapshot where
  fromJSON enc = do
    -- TODO: Should we verify _type?
    snapshotVersion   <- fromJSField enc "version"
    snapshotExpires   <- fromJSField enc "expires"
    snapshotMeta      <- fromJSField enc "meta"
    snapshotInfoRoot  <- FileMap.lookupM snapshotMeta "root.json"
    snapshotInfoTar   <- FileMap.lookupM snapshotMeta "index.tar"
    snapshotInfoTarGz <- FileMap.lookupM snapshotMeta "index.tar.gz" 
    return Snapshot{..}

instance FromJSON ReadJSON (Signed Snapshot) where
  fromJSON = signedFromJSON
