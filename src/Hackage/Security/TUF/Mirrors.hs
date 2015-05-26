module Hackage.Security.TUF.Mirrors (
    -- * TUF types
    Mirrors(..)
  , Mirror(..)
  ) where

import Hackage.Security.JSON
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Patterns
import Hackage.Security.Util.Some

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Mirrors = Mirrors {
    mirrorsVersion :: FileVersion
  , mirrorsExpires :: FileExpires
  , mirrors        :: [Mirror]
  }

data Mirror = Mirror {
    -- | The URL of the mirror which mirrorMetaPath and mirrorTargetsPath are
    -- relative to
    mirrorUrlBase :: String

    -- | All metadata files will be retrieved from mirrorMetaPath
  , mirrorMetaPath :: FilePath

    -- | All target files will be retrieved from mirrorTargetsPath
  , mirrorTargetsPath :: FilePath

    -- | The metadata files available from the mirror
  , mirrorMetaContent :: [Some Pattern]

    -- | The target files available from the mirror
  , mirrorTargetsContent :: [Some Pattern]
  }

instance TUFHeader Mirrors where
  fileVersion = mirrorsVersion
  fileExpires = Just . mirrorsExpires
  describeFile _ = "mirrors list"

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Mirror where
  toJSON Mirror{..} = JSObject [
      ("urlbase"        , toJSON mirrorUrlBase)
    , ("metapath"       , toJSON mirrorMetaPath)
    , ("targetspath"    , toJSON mirrorTargetsPath)
    , ("metacontent"    , toJSON mirrorMetaContent)
    , ("targetscontent" , toJSON mirrorTargetsContent)
    ]

instance ToJSON Mirrors where
  toJSON Mirrors{..} = JSObject [
      ("_type"   , JSString "Mirrorlist")
    , ("version" , toJSON mirrorsVersion)
    , ("expires" , toJSON mirrorsExpires)
    , ("mirrors" , toJSON mirrors)
    ]

instance ReportSchemaErrors m => FromJSON m Mirror where
  fromJSON enc = do
    mirrorUrlBase        <- fromJSField enc "urlbase"
    mirrorMetaPath       <- fromJSField enc "metapath"
    mirrorTargetsPath    <- fromJSField enc "targetspath"
    mirrorMetaContent    <- fromJSField enc "metacontent"
    mirrorTargetsContent <- fromJSField enc "targetscontent"
    return Mirror{..}

instance ReportSchemaErrors m => FromJSON m Mirrors where
  fromJSON enc = do
    -- TODO: Verify _type
    mirrorsVersion <- fromJSField enc "version"
    mirrorsExpires <- fromJSField enc "expires"
    mirrors        <- fromJSField enc "mirrors"
    return Mirrors{..}
