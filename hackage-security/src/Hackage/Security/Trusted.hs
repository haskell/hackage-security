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
  , trustedFileInfoEqual
  ) where

import Data.Function (on)
import Data.Time
import Hackage.Security.TUF
import Hackage.Security.Trusted.TCB hiding (DeclareTrusted)

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

-- | Variation on 'knownFileInfoEqual' for 'Trusted' 'FileInfo'
trustedFileInfoEqual :: Trusted FileInfo -> Trusted FileInfo -> Bool
trustedFileInfoEqual = knownFileInfoEqual `on` trusted
