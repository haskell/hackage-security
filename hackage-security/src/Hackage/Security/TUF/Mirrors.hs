{-# LANGUAGE UndecidableInstances #-}
module Hackage.Security.TUF.Mirrors (
    -- * TUF types
    Mirrors(..)
  , Mirror(..)
  , MirrorContent(..)
    -- ** Utility
  , MirrorDescription
  , describeMirror
  ) where

import Control.Monad.Except
import Network.URI

import Hackage.Security.JSON
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
    mirrorUrlBase :: URI
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

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

type MirrorDescription = String

-- | Give a human-readable description of a particular mirror
--
-- (for use in error messages)
describeMirror :: Mirror -> MirrorDescription
describeMirror = show . mirrorUrlBase

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m Mirror where
  toJSON Mirror{..} = mkObject $ concat [
      [ ("urlbase", toJSON mirrorUrlBase) ]
    , case mirrorContent of
        MirrorFull -> []
    ]

instance Monad m => ToJSON m Mirrors where
  toJSON Mirrors{..} = mkObject [
      ("_type"   , return $ JSString "Mirrorlist")
    , ("version" , toJSON mirrorsVersion)
    , ("expires" , toJSON mirrorsExpires)
    , ("mirrors" , toJSON mirrorsMirrors)
    ]

instance ReportSchemaErrors m => FromJSON m Mirror where
  fromJSON enc = do
    mirrorUrlBase <- fromJSField enc "urlbase"
    let mirrorContent = MirrorFull
    return Mirror{..}

instance ( MonadError DeserializationError m
         , ReportSchemaErrors m
         ) => FromJSON m Mirrors where
  fromJSON enc = do
    verifyType enc "Mirrorlist"
    mirrorsVersion <- fromJSField enc "version"
    mirrorsExpires <- fromJSField enc "expires"
    mirrorsMirrors <- fromJSField enc "mirrors"
    return Mirrors{..}

instance MonadKeys m => FromJSON m (Signed Mirrors) where
  fromJSON = signedFromJSON
