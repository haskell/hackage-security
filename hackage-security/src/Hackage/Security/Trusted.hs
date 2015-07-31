{-# LANGUAGE CPP #-}
#if __GLASGOW_HASKELL__ >= 710
{-# LANGUAGE StaticPointers #-}
#endif
module Hackage.Security.Trusted (
    module Hackage.Security.Trusted.TCB
    -- * Derived functions
  , (<$$>)
    -- ** Role verification
  , VerifyRole(..)
    -- ** File info verification
  , verifyFileInfo
  , trustedFileInfoEqual
  ) where

import Data.Function (on)
import Data.Time
import Hackage.Security.TUF
import Hackage.Security.Trusted.TCB hiding (DeclareTrusted)
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Combinators on trusted values
-------------------------------------------------------------------------------}

-- | Apply a static function to a trusted argument
(<$$>) :: StaticPtr (a -> b) -> Trusted a -> Trusted b
(<$$>) = trustApply . trustStatic

{-------------------------------------------------------------------------------
  Role verification
-------------------------------------------------------------------------------}

class VerifyRole a where
  verifyRole :: Trusted Root      -- ^ Root data
             -> TargetPath        -- ^ Source (for error messages)
             -> Maybe FileVersion -- ^ Previous version (if available)
             -> Maybe UTCTime     -- ^ Time now (if checking expiry)
             -> Signed a          -- ^ Mirrors to verify
             -> Either VerificationError (SignaturesVerified a)

instance VerifyRole Root where
  verifyRole = verifyRole' . (static (rootRolesRoot . rootRoles) <$$>)

instance VerifyRole Timestamp where
  verifyRole = verifyRole' . (static (rootRolesTimestamp . rootRoles) <$$>)

instance VerifyRole Snapshot where
  verifyRole = verifyRole' . (static (rootRolesSnapshot . rootRoles) <$$>)

instance VerifyRole Mirrors where
  verifyRole = verifyRole' . (static (rootRolesMirrors . rootRoles) <$$>)

{-------------------------------------------------------------------------------
  File info verification
-------------------------------------------------------------------------------}

-- | Verify 'FileInfo'
--
-- We compare file lengths before computing hashes, but once we have verified
-- that the file lengths match we compute _all_ hashes, and then compare the
-- resulting sets. This is the right thing to do: sure, in the case where the
-- file info does _not_ match this is a waste of effort. However, we expect
-- that in the majority of cases the file info _will_ match, in which case
-- having to traverse the file multiple times to compute each hash, rather than
-- traversing the file once and computing all hashes at once, is inefficient.
--
-- (Of course, right now the difference is moot since we only use one hash.)
verifyFileInfo :: forall root. IsFileSystemRoot root
               => Path (Rooted root) -> Trusted FileInfo -> IO Bool
verifyFileInfo fp trustedInfo = lazyAndM [
      verifyFileLength
    , (knownFileInfoEqual info) <$> computeFileInfo fp
    ]
  where
    verifyFileLength :: IO Bool
    verifyFileLength = (== fileInfoLength) <$> getFileLength

    getFileLength :: IO FileLength
    getFileLength = FileLength . fromInteger <$> getFileSize fp

    info@FileInfo{..} = trusted trustedInfo

-- | Variation on 'knownFileInfoEqual' for 'Trusted' 'FileInfo'
trustedFileInfoEqual :: Trusted FileInfo -> Trusted FileInfo -> Bool
trustedFileInfoEqual = knownFileInfoEqual `on` trusted

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

lazyAndM :: Monad m => [m Bool] -> m Bool
lazyAndM []     = return True
lazyAndM (m:ms) = do b <- m
                     case b of
                       False -> return False
                       True  -> lazyAndM ms
