module Hackage.Security.TUF.Mirrors (
    -- * TUF types
    Mirrors(..)
  , Mirror(..)
  , MirrorContent(..)
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Signed

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Mirrors = Mirrors {
    mirrorsVersion :: FileVersion
  , mirrorsExpires :: FileExpires
  , mirrorsMirrors :: [Mirror]
  }

-- | Definition of a mirror
--
-- NOTE: Unlike the TUF specification, we require that all mirrors must have
-- the same format. That is, we omit @metapath@ and @targetspath@.
data Mirror = Mirror {
    mirrorUrlBase :: String
  , mirrorContent :: MirrorContent
  }
  deriving Show

-- | Full versus partial mirrors
--
-- The TUF spec explicitly allows for partial mirrors, with the mirrors file
-- specifying (through patterns) what is available from partial mirrors.
--
-- For now we only support full mirrors; if we wanted to add partial mirrors,
-- we would add a second @MirrorPartial@ constructor here with arguments
-- corresponding to TUF's @metacontent@ and @targetscontent@ fields.
data MirrorContent =
    MirrorFull
  deriving Show

instance HasHeader Mirrors where
  fileVersion f x = (\y -> x { mirrorsVersion = y }) <$> f (mirrorsVersion x)
  fileExpires f x = (\y -> x { mirrorsExpires = y }) <$> f (mirrorsExpires x)

instance DescribeFile Mirrors where
  describeFile _ = "mirrors list"

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Mirror where
  toJSON Mirror{..} = JSObject $ concat [
      [ ("urlbase"        , toJSON mirrorUrlBase)
      ]
    , case mirrorContent of
        MirrorFull -> []
    ]

instance ToJSON Mirrors where
  toJSON Mirrors{..} = JSObject [
      ("_type"   , JSString "Mirrorlist")
    , ("version" , toJSON mirrorsVersion)
    , ("expires" , toJSON mirrorsExpires)
    , ("mirrors" , toJSON mirrorsMirrors)
    ]

instance ReportSchemaErrors m => FromJSON m Mirror where
  fromJSON enc = do
    mirrorUrlBase <- fromJSField enc "urlbase"
    let mirrorContent = MirrorFull
    return Mirror{..}

instance ReportSchemaErrors m => FromJSON m Mirrors where
  fromJSON enc = do
    -- TODO: Verify _type
    mirrorsVersion <- fromJSField enc "version"
    mirrorsExpires <- fromJSField enc "expires"
    mirrorsMirrors <- fromJSField enc "mirrors"
    return Mirrors{..}

instance FromJSON ReadJSON (Signed Mirrors) where
  fromJSON = signedFromJSON
