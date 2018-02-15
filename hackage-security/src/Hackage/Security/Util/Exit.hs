module Hackage.Security.Util.Exit where

import Control.Monad.Except

{-------------------------------------------------------------------------------
  Auxiliary: multiple exit points
-------------------------------------------------------------------------------}

-- | Multiple exit points
--
-- We can simulate the imperative code
--
-- > if (cond1)
-- >   return exp1;
-- > if (cond2)
-- >   return exp2;
-- > if (cond3)
-- >   return exp3;
-- > return exp4;
--
-- as
--
-- > multipleExitPoints $ do
-- >   when (cond1) $
-- >     exit exp1
-- >   when (cond2) $
-- >     exit exp2
-- >   when (cond3) $
-- >     exit exp3
-- >   return exp4
multipleExitPoints :: Monad m => ExceptT a m a -> m a
multipleExitPoints = liftM aux . runExceptT
  where
    aux :: Either a a -> a
    aux (Left  a) = a
    aux (Right a) = a

-- | Function exit point (see 'multipleExitPoints')
exit :: Monad m => e -> ExceptT e m a
exit = throwError
