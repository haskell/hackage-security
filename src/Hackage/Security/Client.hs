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
  | FileIndexTarball

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Download a file from the server
    repGetRemote :: File -> IO FilePath

    -- | Get a cached file
    --
    -- NOTE: We expect this to succeed always. In particular, it means that
    -- "new" clients (that have never communicated with the server before)
    -- must be given initial root data, as well as a corresponding snapshot
    -- containing the hash of that root data and a corresponding timestamp.
    -- If we didn't do this, the logic in 'checkForUpdates' (such as "did the
    -- root data change?") would be a lot more cumbersome.
  , repGetCached :: File -> IO FilePath
  }

{-------------------------------------------------------------------------------
  Checking for updates
-------------------------------------------------------------------------------}

-- | Should we check expiry dates?
data CheckExpiry =
    -- | Yes, check expiry dates
    CheckExpiry

    -- | No, don't check expiry dates.
    --
    -- This should ONLY be used in exceptional circumstances (such as when
    -- the main server is down for longer than the expiry dates used in the
    -- timestamp files on mirrors).
  | DontCheckExpiry

data HasUpdates = HasUpdates | NoUpdates

-- | Generic logic for checking if there are updates
--
-- This implements the logic described in Section 5.1, "The client application",
-- of the TUF spec.
--
-- TODO: We need to catch exceptions and if we catch one, update the root
-- and start over.
checkForUpdates :: CheckExpiry -> Repository -> IO HasUpdates
checkForUpdates checkExpiry Repository{..} = do
    mNow <- case checkExpiry of
              CheckExpiry     -> Just <$> getCurrentTime
              DontCheckExpiry -> return Nothing

    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    cachedRoot :: Trusted Root
       <- repGetCached FileRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
    let keyEnv = rootKeys (trusted cachedRoot)

    -- Get the old timestamp
    oldTS :: Trusted Timestamp
       <- repGetCached FileTimestamp
      >>= readJSON keyEnv
      >>= return . trustLocalFile

    -- Get the new timestamp
    newTS :: Trusted Timestamp
       <- repGetRemote FileTimestamp
      >>= readJSON keyEnv
      >>= throwErrors . verifyTimestamp
            cachedRoot
            (fileVersion oldTS)
            mNow

    -- Check if the snapshot has changed
    if snapshotFileInfo newTS /= snapshotFileInfo oldTS
      then return NoUpdates
      else do
        -- Get the old snapshot (if any)
        oldSS :: Trusted Snapshot
           <- repGetCached FileSnapshot
          >>= readJSON keyEnv
          >>= return . trustLocalFile

        -- Get the new snapshot
        newSS :: Trusted Snapshot
           <- repGetRemote FileSnapshot
          >>= readJSON keyEnv
          >>= throwErrors . verifySnapshot
                cachedRoot
                (snapshotFileInfo newTS)
                (fileVersion oldSS)
                mNow

        -- Check which files have changed
        let fileChanges = fileMapChanges (snapshotMeta (trusted oldSS))
                                         (snapshotMeta (trusted newSS))

        -- If root metadata changed, update and restart
        when (FileChanged "root.json" `elem` fileChanges) $
          updateRoot

        -- If index has changed, download it and verify it
        when (FileChanged "index.tar" `elem` fileChanges) $
          -- TODO: verify
          void $ repGetCached FileIndexTarball

        return HasUpdates
  where
    -- TODO
    updateRoot :: IO ()
    updateRoot = return ()

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Local files are assumed trusted
trustLocalFile :: Signed a -> Trusted a
trustLocalFile Signed{..} = DeclareTrusted signed

readJSON :: FromJSON ReadJSON a => KeyEnv -> FilePath -> IO a
readJSON keyEnv fpath = do
    result <- readCanonical keyEnv fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

throwErrors :: Exception e => Either e a -> IO a
throwErrors (Left err) = throwIO err
throwErrors (Right a)  = return a
