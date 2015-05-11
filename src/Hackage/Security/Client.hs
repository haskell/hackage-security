module Hackage.Security.Client (
    Repository(..)
  , File(..)
    -- * Checking for updates
  , HasUpdates(..)
  , checkForUpdates
  ) where

import Control.Exception
import Control.Monad hiding (forM_)
import Data.Foldable (forM_)
import Data.Time
import Data.Typeable (Typeable)

import Hackage.Security.JSON
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF
import qualified Hackage.Security.Key.Env as KeyEnv

data File =
    -- | The snapshot metadata (@snapshot.json@)
    FileSnapshot

    -- | The timestamp metadata (@timestamp.json@)
  | FileTimestamp

    -- | The root metadata (@root.json@)
  | FileRoot

    -- | The index
    --
    -- When we request that the index is downloaded, it is up to the repository
    -- to decide whether to download @00-index.tar@ or @00-index.tar.gz@.
  | FileIndex

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Download a file from the server (but don't trust it yet)
    repGetRemote :: File -> IO FilePath

    -- | Trust a previously downloaded remote file
  , repTrust :: File -> IO ()

    -- | Get a cached file
  , repGetCached :: File -> IO (Maybe FilePath)

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO FilePath

    -- | Delete a previously downloaded remote file
    -- (probably because the root metadata changed)
  , repDeleteCached :: File -> IO ()
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
checkForUpdates :: Repository -> CheckExpiry -> IO HasUpdates
checkForUpdates rep@Repository{..} checkExpiry = do
    mNow <- case checkExpiry of
              CheckExpiry     -> Just <$> getCurrentTime
              DontCheckExpiry -> return Nothing

    -- TODO: Should we cap how often we go round this loop?
    catches (go mNow) [
        Handler $ \(_ex :: VerificationError) -> do
          -- NOTE: This call to updateRoot is not itself protected by an
          -- exception handler, and may therefore throw a VerificationError.
          -- This is intentional: if we get verification errors during the
          -- update process, _and_ we cannot update the main root info, then
          -- we cannot do anything.
          updateRoot rep mNow Nothing
          checkForUpdates rep checkExpiry
      , Handler $ \(_ex :: RootUpdated) -> do
          checkForUpdates rep checkExpiry
      ]
  where
    go :: Maybe UTCTime -> IO HasUpdates
    go mNow = do
      -- We need the cached root information in order to resolve key IDs and
      -- verify signatures
      cachedRoot :: Trusted Root
         <- repGetCachedRoot
        >>= readJSON KeyEnv.empty
        >>= return . trustLocalFile
      let keyEnv = rootKeys (trusted cachedRoot)

      -- Get the old timestamp (if any)
      mOldTS :: Maybe (Trusted Timestamp)
         <- repGetCached FileTimestamp
        >>= traverse (readJSON keyEnv)
        >>= return . fmap trustLocalFile

      -- Get the new timestamp
      newTS :: Trusted Timestamp
         <- repGetRemote FileTimestamp
        >>= readJSON keyEnv
        >>= throwErrors . verifyTimestamp
              cachedRoot
              (fmap fileVersion mOldTS)
              mNow
      repTrust FileTimestamp

      -- Check if the snapshot has changed
      case checkChanged (fmap trustedTimestampInfoSnapshot mOldTS)
                        (trustedTimestampInfoSnapshot newTS) of
        Nothing ->
          return NoUpdates
        Just updatedSnapshotInfo -> do
          -- Get the old snapshot (if any)
          mOldSS :: Maybe (Trusted Snapshot)
             <- repGetCached FileSnapshot
            >>= traverse (readJSON keyEnv)
            >>= return . fmap trustLocalFile

          -- Get the new snapshot
          newSS :: Trusted Snapshot
             <- repGetRemote FileSnapshot
            >>= readJSON keyEnv
            >>= throwErrors . verifySnapshot
                  cachedRoot
                  updatedSnapshotInfo
                  (fmap fileVersion mOldSS)
                  mNow
          repTrust FileSnapshot

          -- If root metadata changed, update and restart
          let mOldRootInfo = fmap trustedSnapshotInfoRoot mOldSS
              newRootInfo  = trustedSnapshotInfoRoot newSS
          forM_ (checkChanged mOldRootInfo newRootInfo) $ \updatedRootInfo -> do
            updateRoot rep mNow (Just updatedRootInfo)
            throwIO RootUpdated

          -- If the index changed, download it and verify it
          let mOldIndexInfo = fmap trustedSnapshotInfoTar mOldSS
              newIndexInfo  = trustedSnapshotInfoTar newSS
          forM_ (checkChanged mOldIndexInfo newIndexInfo) $ \updatedTarInfo -> do
            indexTar     <- repGetRemote FileIndex
            indexTarInfo <- fileInfoTargetFile indexTar
            unless (verifyFileInfo updatedTarInfo indexTarInfo) $
              throwIO VerificationErrorFileInfo
            repTrust FileIndex

          -- TODO: We should now verify all target files, but until we have
          -- author signing this is not necessary.

          return HasUpdates

    checkChanged :: Maybe (Trusted FileInfo)  -- ^ Old
                 -> Trusted FileInfo          -- ^ New
                 -> Maybe (Trusted FileInfo)  -- ^ New, if different from old
    checkChanged Nothing    new = Just new
    checkChanged (Just old) new = if old == new then Nothing else Just new

-- | Root metadata updated
--
-- We throw this when we (succesfully) updated the root metadata as part of the
-- normal update process so that we know to restart it.
data RootUpdated = RootUpdated
  deriving (Show, Typeable)

instance Exception RootUpdated

-- | Update the root metadata
--
-- Note that the new root metadata is verified using the old root metadata,
-- and only then trusted.
updateRoot :: Repository -> Maybe UTCTime -> Maybe (Trusted FileInfo) -> IO ()
updateRoot Repository{..} mNow mFileInfo = do
    oldRoot :: Trusted Root
       <- repGetCachedRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile

    _newRoot :: Trusted Root
       <- repGetRemote FileRoot
      >>= readJSON KeyEnv.empty
      >>= throwErrors . verifyRoot oldRoot mFileInfo mNow

    repTrust FileRoot
    repDeleteCached FileTimestamp
    repDeleteCached FileSnapshot

{-------------------------------------------------------------------------------
  Downloading target files
-------------------------------------------------------------------------------}



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
