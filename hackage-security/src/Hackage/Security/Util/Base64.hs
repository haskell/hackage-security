module Hackage.Security.Util.Base64 (
    Base64 -- opaque
  , fromByteString
  , toByteString
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8  as C8  -- only called on B64-enc strings
import qualified Data.ByteString.Base64 as B64

import Hackage.Security.Util.JSON

-- | Simple wrapper around bytestring with ToJSON and FromJSON instances that
-- use base64 encoding.
newtype Base64 = Base64 ByteString

fromByteString :: ByteString -> Base64
fromByteString = Base64

toByteString :: Base64 -> ByteString
toByteString (Base64 bs) = bs

instance Monad m => ToJSON m Base64 where
  toJSON (Base64 bs) = toJSON (C8.unpack (B64.encode bs))

instance ReportSchemaErrors m => FromJSON m Base64 where
  fromJSON val = do
    str <- fromJSON val
    case B64.decode (C8.pack str) of
      Left _err -> expected "base-64 encoded string" Nothing
      Right bs  -> return $ Base64 bs
