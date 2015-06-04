module Hackage.Security.Trusted.Unsafe (
    Trusted(DeclareTrusted, trusted)
  ) where

import Hackage.Security.TUF.Header

-- | A trusted value
--
-- Although we do not specify exactly what we mean by trusted, the main idea
-- is that trusted data can only be obtained from other trusted data or through
-- explicit verification.
--
-- The 'DeclareTrusted' constructor is exported only in the
-- "Hackage.Security.Trusted.Unsafe" module, and any direct use of this
-- constructor should be considered a proof obligation.
newtype Trusted a = DeclareTrusted { trusted :: a }
  deriving (Eq, Ord, Show, DescribeFile)
