-- | Checked exceptions
module Hackage.Security.Util.Checked (
    Throws(..)
  , checkIO
  , rethrowUnchecked
  , catchChecked
  , handleChecked
  , throwUnchecked
  ) where

import Control.Exception
import Unsafe.Coerce (unsafeCoerce)

{-------------------------------------------------------------------------------
  Checked exceptions
-------------------------------------------------------------------------------}

-- | Checked exceptions
class Throws e where
  throwChecked :: e -> IO a

-- | Rethrow IO exceptions as checked exceptions
checkIO :: Throws IOException => IO a -> IO a
checkIO = handle $ \(ex :: IOException) -> throwChecked ex

-- | Rethrow checked exceptions as unchecked (regular) exceptions
rethrowUnchecked :: forall e a. (Throws e => IO a) -> (Exception e => IO a)
rethrowUnchecked act = aux act throw
  where
    aux :: (Throws e => IO a) -> ((e -> IO a) -> IO a)
    aux = unsafeCoerce

-- | Catch a checked exception
--
-- This is the only way to discharge a 'Throws' type class constraint.
catchChecked :: Exception e => (Throws e => IO a) -> (e -> IO a) -> IO a
catchChecked = catch . rethrowUnchecked

-- | 'catchChecked' with the arguments reversed
handleChecked :: Exception e => (e -> IO a) -> (Throws e => IO a) -> IO a
handleChecked = flip catchChecked

-- | Throw an unchecked exception
--
-- This is just an alias for 'throw', but makes it evident that this is a very
-- intentional use of an unchecked exception.
throwUnchecked :: Exception e => e -> IO a
throwUnchecked = throwIO
