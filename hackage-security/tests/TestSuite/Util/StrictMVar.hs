module TestSuite.Util.StrictMVar (
    MVar -- opaque
  , newMVar
  , CC.withMVar
  , modifyMVar
  , modifyMVar_
  , CC.readMVar
  ) where

import Control.Concurrent (MVar)
import Control.Exception
import qualified Control.Concurrent as CC

newMVar :: a -> IO (MVar a)
newMVar x = CC.newMVar =<< evaluate x

modifyMVar :: MVar a -> (a -> IO (a, b)) -> IO b
modifyMVar mv f = CC.modifyMVar mv $ \old -> do
    (new, ret) <- f old
    new' <- evaluate new
    return (new', ret)

modifyMVar_ :: MVar a -> (a -> IO a) -> IO ()
modifyMVar_ mv f = modifyMVar mv (returnUnit . f)
  where
    returnUnit :: IO a -> IO (a, ())
    returnUnit = fmap $ \a -> (a, ())
