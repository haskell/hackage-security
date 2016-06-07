{-# LANGUAGE CPP #-}
{-# OPTIONS_GHC -fno-warn-unused-binds #-}
#if __GLASGOW_HASKELL__ >= 800
{-# OPTIONS_GHC -Wno-redundant-constraints #-}
#endif

#if __GLASGOW_HASKELL__ >= 708
{-# LANGUAGE RoleAnnotations     #-}
{-# LANGUAGE IncoherentInstances #-}
#endif

-- | Checked exceptions
module Hackage.Security.Util.Checked (
    Throws
  , unthrow
    -- ** Base exceptions
  , throwChecked
  , catchChecked
  , handleChecked
  , tryChecked
  , checkIO
  , throwUnchecked
  , internalError
  ) where

import Control.Exception (Exception, IOException)
import qualified Control.Exception as Base

#if __GLASGOW_HASKELL__ >= 708
import GHC.Prim (coerce)
#else
import Unsafe.Coerce (unsafeCoerce)
#endif

{-------------------------------------------------------------------------------
  Basic infrastructure
-------------------------------------------------------------------------------}

-- | Checked exceptions
class Throws e where

#if __GLASGOW_HASKELL__ >= 708
type role Throws representational
#endif

unthrow :: forall a e proxy . proxy e -> (Throws e => a) -> a
unthrow _ x = unWrap (coerceWrap (Wrap x :: Wrap e a))

{-------------------------------------------------------------------------------
  Base exceptions
-------------------------------------------------------------------------------}

-- | Throw a checked exception
throwChecked :: (Exception e, Throws e) => e -> IO a
throwChecked = Base.throwIO

-- | Catch a checked exception
catchChecked :: forall a e. Exception e
             => (Throws e => IO a) -> (e -> IO a) -> IO a
catchChecked act = Base.catch (unthrow (Proxy :: Proxy e) act)

-- | 'catchChecked' with the arguments reversed
handleChecked :: Exception e => (e -> IO a) -> (Throws e => IO a) -> IO a
handleChecked act handler = catchChecked handler act

-- | Like 'try', but for checked exceptions
tryChecked :: Exception e => (Throws e => IO a) -> IO (Either e a)
tryChecked act = catchChecked (Right <$> act) (return . Left)

-- | Rethrow IO exceptions as checked exceptions
checkIO :: Throws IOException => IO a -> IO a
checkIO = Base.handle $ \(ex :: IOException) -> throwChecked ex

-- | Throw an unchecked exception
--
-- This is just an alias for 'throw', but makes it evident that this is a very
-- intentional use of an unchecked exception.
throwUnchecked :: Exception e => e -> IO a
throwUnchecked = Base.throwIO

-- | Variation on 'throwUnchecked' for internal errors
internalError :: String -> IO a
internalError = throwUnchecked . userError

{-------------------------------------------------------------------------------
  Auxiliary definitions (not exported)
-------------------------------------------------------------------------------}

-- | Wrap an action that may throw a checked exception
--
-- This is used internally in 'unthrow' to avoid impredicative
-- instantiation of the type of 'coerce'/'unsafeCoerce'.
newtype Wrap e a = Wrap { unWrap :: Throws e => a }

coerceWrap :: Wrap e a -> Wrap (Catch e) a
#if __GLASGOW_HASKELL__ >= 708
coerceWrap = coerce
#else
coerceWrap = unsafeCoerce
#endif

data Proxy a = Proxy

newtype Catch a = Catch a
instance Throws (Catch e) where
