module Hackage.Security.Client (
    Repository(..)
  , File(..)
    -- * Checking for updates
  , HasUpdates(..)
  , checkForUpdates
  ) where

import Control.Exception
import Control.Monad
import Data.Time

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF
import qualified Hackage.Security.Key.Env as KeyEnv

data File =
    FileSnapshot
  | FileTimestamp
  | FileRoot

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Download a file from the server
    repGetRemote :: File -> IO FilePath

    -- | Get a cached file (if it exists)
  , repGetCached :: File -> IO (Maybe FilePath)

    -- | Get the (cached) root metadata
    --
    -- This must always succeed; how the initial root metadata is distributed
    -- to clients is outside the scope of this module.
  , repGetRoot :: IO FilePath
  }

{-------------------------------------------------------------------------------
  Checking for updates
-------------------------------------------------------------------------------}

data HasUpdates = HasUpdates | NoUpdates

-- | Generic logic for checking if there are updates
--
-- This implements the logic described in Section 5.1, "The client application",
-- of the TUF spec.
checkForUpdates :: Repository -> IO HasUpdates
checkForUpdates Repository{..} = do
    -- TODO: We should make checking expiry dates optional
    now <- getCurrentTime

    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    cachedRoot :: Trusted Root
       <- repGetRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
    let keyEnv = rootKeys (trusted cachedRoot)

    -- Get the old timestamp (if any)
    mOldTS :: Maybe (Trusted Timestamp)
       <- repGetCached FileTimestamp
      >>= readOptJSON keyEnv
      >>= return . fmap trustLocalFile

    -- Get the new timestamp
    newTS :: Trusted Timestamp
       <- repGetRemote FileTimestamp
      >>= readJSON keyEnv
      >>= throwErrors . verifyTimestamp
            cachedRoot
            (fmap fileVersion mOldTS)
            (Just now)

    -- Check if the snapshot has changed
    let snapshotChanged =
          case mOldTS of
            Nothing    -> True
            Just oldTS -> snapshotFileInfo newTS /= snapshotFileInfo oldTS
    if not snapshotChanged
      then return NoUpdates
      else do
        -- Get the old snapshot (if any)
        mOldSS :: Maybe (Trusted Snapshot)
           <- repGetCached FileSnapshot
          >>= readOptJSON keyEnv
          >>= return . fmap trustLocalFile

        -- Get the new snapshot
        newSS :: Trusted Snapshot
           <- repGetRemote FileSnapshot
          >>= readJSON keyEnv
          >>= throwErrors . verifySnapshot
                cachedRoot
                (snapshotFileInfo newTS)
                (fmap fileVersion mOldSS)
                (Just now)

        return HasUpdates

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

readJSON :: FromJSON ReadJSON a => KeyEnv -> FilePath -> IO a
readJSON keyEnv fpath = do
    result <- readCanonical keyEnv fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

readOptJSON :: FromJSON ReadJSON a => KeyEnv -> Maybe FilePath -> IO (Maybe a)
readOptJSON _      Nothing      = return Nothing
readOptJSON keyEnv (Just fpath) = Just <$> readJSON keyEnv fpath

-- | Local files are assumed trusted
trustLocalFile :: Signed a -> Trusted a
trustLocalFile Signed{..} = DeclareTrusted signed

throwErrors :: Exception e => Either e a -> IO a
throwErrors (Left err) = throwIO err
throwErrors (Right a)  = return a
