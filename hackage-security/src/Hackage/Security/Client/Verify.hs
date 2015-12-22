module Hackage.Security.Client.Verify (
    -- * Verification monad
    Verify -- opaque
  , runVerify
  , acquire
  , ifVerified
    -- * Specific resources
  , openTempFile
    -- * Re-exports
  , liftIO
  ) where

import Control.Exception
import Control.Monad.Reader
import Data.IORef

import Hackage.Security.Util.IO
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Verification monad
-------------------------------------------------------------------------------}

type Finaliser = IO ()
type Cleanup   = IO ()

-- | Verification monad
--
-- The verification monad is similar to 'ResourceT' in intent, in that we can
-- register handlers to be run to release resources. Unlike 'ResourceT',
-- however, we maintain _two_ handlers: a cleanup handler which is run  whether
-- or not verification succeeds, and a finalisation handler which is run only if
-- verification succeeds.
--
-- * Cleanup handlers are registered using 'acquire', and are guaranteed to run
--   just before the computation terminates (after the finalisation handler).
-- * The finalisation handlers are run only when verification succeeds, and can
--   be registered with 'ifVerified'. Finalisation can be used for instance to
--   update the local cache (which should only happen if verification is
--   successful).
newtype Verify a = Verify {
    unVerify :: ReaderT (IORef Cleanup, IORef Finaliser) IO a
  }
  deriving (Functor, Applicative, Monad, MonadIO)

-- | Run an action in the 'Verify' monad
runVerify :: (Finaliser -> Finaliser) -> Verify a -> IO a
runVerify modifyFinaliser v = do
    rCleanup   <- newIORef $ return ()
    rFinaliser <- newIORef $ return ()
    mask $ \restore -> do
      ma <- try $ restore $ runReaderT (unVerify v) (rCleanup, rFinaliser)
      case ma of
        Left ex -> do join $ readIORef rCleanup
                      throwIO (ex :: SomeException)
        Right a -> do modifyFinaliser $ join $ readIORef rFinaliser
                      join $ readIORef rCleanup
                      return a

-- | Acquire a resource and register the corresponding cleanup handler
--
-- NOTE: Resource acquisition happens with exceptions masked. If it is important
-- that the resource acquistion can be timed out (or receive other kinds of
-- asynchronous exceptions), you will need to use an interruptible operation.
-- See <http://www.well-typed.com/blog/2014/08/asynchronous-exceptions/> for
-- details.
acquire :: IO a -> (a -> IO ()) -> Verify a
acquire get release = Verify $ do
    (rCleanup, _rFinaliser) <- ask
    liftIO $ mask_ $ do
      a <- liftIO get
      modifyIORef rCleanup (>> release a)
      return a

-- | Register an action to be run only if verification succeeds
ifVerified :: IO () -> Verify ()
ifVerified handler = Verify $ do
    (_rCleanup, rFinaliser) <- ask
    liftIO $ modifyIORef rFinaliser (>> handler)

{-------------------------------------------------------------------------------
  Specific resources
-------------------------------------------------------------------------------}

-- | Create a short-lived temporary file
--
-- Creates the directory where the temp file should live if it does not exist.
openTempFile :: FsRoot root
             => Path root  -- ^ Temp directory
             -> String     -- ^ Template
             -> Verify (Path Absolute, Handle)
openTempFile tmpDir template =
    acquire createTempFile closeAndDelete
  where
    createTempFile :: IO (Path Absolute, Handle)
    createTempFile = do
      createDirectoryIfMissing True tmpDir
      openTempFile' tmpDir template

    closeAndDelete :: (Path Absolute, Handle) -> IO ()
    closeAndDelete (fp, h) = do
      hClose h
      void $ handleDoesNotExist $ removeFile fp
