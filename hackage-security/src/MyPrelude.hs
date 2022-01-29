-- | Smooth over differences between various ghc versions by making older
-- preludes look like 4.8.0
{-# LANGUAGE CPP #-}
module MyPrelude (
    module P
#if !MIN_VERSION_base(4,8,0)
  , Applicative(..)
  , Monoid(..)
  , (<$>)
  , (<$)
  , Traversable(traverse)
  , displayException
#endif
  ) where

#if MIN_VERSION_base(4,8,0)
import Prelude as P
#else
#if MIN_VERSION_base(4,6,0)
import Prelude as P
#else
import Prelude as P hiding (catch)
#endif
import Control.Applicative
import Control.Exception (Exception)
import Data.Monoid
import Data.Traversable (Traversable(traverse))

displayException :: Exception e => e -> String
displayException = show
#endif
