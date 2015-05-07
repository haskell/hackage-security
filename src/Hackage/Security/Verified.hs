module Hackage.Security.Verified (
    Verified -- opaque
  , verified
    -- * Role verification
  , VerificationInfo -- opaque
  , verifyRole
  ) where

import Control.Exception
import Control.Monad.Except
import Data.Time
import Data.Typeable (Typeable)

import Hackage.Security.TUF

newtype Verified a = Verified { verified :: a }

{-------------------------------------------------------------------------------
  Role verification
-------------------------------------------------------------------------------}

data RoleVerificationError =
     RoleVerificationErrorSignatures
   | RoleVerificationErrorExpired
   | RoleVerificationErrorVersion
   deriving (Show, Typeable)

instance Exception RoleVerificationError

-- | Role verification
--
-- NOTE: We throw an error here if the file version decreased, but we do NOT
-- check anything when the file version remains the same. It is the
-- responsiblity of the calling code to deal with this case.
verifyRole :: forall a. VerificationInfo a
           => RoleSpec           -- ^ Role specification to verify signatures
           -> Maybe FileVersion  -- ^ Previous file version (if any)
           -> Maybe UTCTime      -- ^ Time it is now to check expiry (if using)
           -> Signed a -> Either RoleVerificationError (Verified a)
verifyRole role mPrev mNow Signed{..} = runExcept go
  where
    go :: Except RoleVerificationError (Verified a)
    go = do
      -- Verify expiry date
      case mNow of
        Nothing  -> return ()
        Just now -> do
          when (expires signed < now) $
            throwError RoleVerificationErrorExpired

      -- Verify timestamp
      case mPrev of
        Nothing   -> return ()
        Just prev -> do
          when (version signed < prev) $
            throwError RoleVerificationErrorVersion

      -- Verify signatures
      unless (verifyThreshold role signatures) $
        throwError RoleVerificationErrorSignatures

      -- Everything is A-OK!
      return $ Verified signed

{-------------------------------------------------------------------------------
  Auxiliary: all TUF types have a timestamp and a version number
-------------------------------------------------------------------------------}

class VerificationInfo a where
  expires :: a -> UTCTime
  version :: a -> FileVersion

instance VerificationInfo Timestamp where
  expires = _timestampExpires
  version = _timestampVersion
