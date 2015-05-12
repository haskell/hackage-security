module Hackage.Security.Client (
    Repository(..)
  , File(..)
    -- * Checking for updates
  , HasUpdates(..)
  , checkForUpdates
    -- * Downloading targets
  , downloadPackage
  ) where

import Control.Exception
import Control.Monad hiding (forM_)
import Data.Foldable (forM_)
import Data.Time
import Data.Typeable (Typeable)
import System.FilePath

import Distribution.Package (PackageIdentifier)
import Distribution.Text

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

    -- | An actual package
  | FilePackage PackageIdentifier

    -- | Target file for a specific package
  | FilePackageMetadata PackageIdentifier

type TemporaryPath = FilePath
type PermanentPath = FilePath

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Get a file from the server
    --
    -- It is the responsibility of the callback to verify the downloaded file.
    -- Only when the callback returns without throwing an exception should be
    -- the file be trusted and moved to a permanent location.
    repWithRemote :: forall a. File -> (TemporaryPath -> IO a) -> IO a

    -- | Get a cached file (if available)
  , repGetCached :: File -> IO (Maybe PermanentPath)

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO PermanentPath

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
        <- repWithRemote FileTimestamp
               $ readJSON keyEnv
             >=> throwErrors . verifyTimestamp
                   cachedRoot
                   (fmap fileVersion mOldTS)
                   mNow

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
             <- repWithRemote FileSnapshot
                    $ readJSON keyEnv
                  >=> throwErrors . verifySnapshot
                        cachedRoot
                        updatedSnapshotInfo
                        (fmap fileVersion mOldSS)
                        mNow

          -- If root metadata changed, update and restart
          let mOldRootInfo = fmap trustedSnapshotInfoRoot mOldSS
              newRootInfo  = trustedSnapshotInfoRoot newSS
          forM_ (checkChanged mOldRootInfo newRootInfo) $ \updatedRootInfo -> do
            updateRoot rep mNow (Just updatedRootInfo)
            throwIO RootUpdated

          -- If the index changed, download it and verify it
          let mOldIndexInfo = fmap trustedSnapshotInfoTar mOldSS
              newIndexInfo  = trustedSnapshotInfoTar newSS
          forM_ (checkChanged mOldIndexInfo newIndexInfo) $ \updatedTarInfo ->
            repWithRemote FileIndex $ \indexTar -> do
              indexTarInfo <- fileInfoTargetFile indexTar
              unless (verifyFileInfo updatedTarInfo indexTarInfo) $
                throwIO VerificationErrorFileInfo

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
       <- repWithRemote FileRoot
              $ readJSON KeyEnv.empty
            >=> throwErrors . verifyRoot oldRoot mFileInfo mNow

    repDeleteCached FileTimestamp
    repDeleteCached FileSnapshot

{-------------------------------------------------------------------------------
  Downloading target files
-------------------------------------------------------------------------------}

-- | Download a package
--
-- It is the responsibility of the callback to move the package from its
-- temporary location to a permanent location (if desired). The callback will
-- only be invoked once the chain of trust has been verified.
--
-- Possibly exceptions thrown:
--
-- * May throw a VerificationError if the package cannot be verified against
--   the previously downloaded metadata. It is up to the calling code to decide
--   what to do with such an exception; in particular, we do NOT automatically
--   renew the root metadata at this point (this matches the TUF spec).
-- * May throw an InvalidPackageException if the requested package does not
--   exist (this is a programmer error).
downloadPackage :: Repository -> PackageIdentifier -> (TemporaryPath -> IO a) -> IO a
downloadPackage Repository{..} pkgId callback = do
    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    cachedRoot :: Trusted Root
       <- repGetCachedRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
    let keyEnv = rootKeys (trusted cachedRoot)

    -- Get the metadata (from the previously updated index)
    targets :: Trusted Targets
       <- repGetCached (FilePackageMetadata pkgId)
      >>= packageMustExist
      >>= readJSON keyEnv
      >>= return . trustLocalFile

    targetMetaData :: Trusted FileInfo
      <- case trustedTargetsLookup packageFileName targets of
           Nothing  -> throwIO VerificationErrorUnknownTarget
           Just nfo -> return nfo

    -- TODO: should we check if cached package available? (spec says no)
    repWithRemote (FilePackage pkgId) $ \tarGz -> do
        -- Verify the fileinfo
        tarGzInfo <- fileInfoTargetFile tarGz
        unless (verifyFileInfo targetMetaData tarGzInfo) $
          throwIO VerificationErrorFileInfo

        -- Invoke the callback
        callback tarGz
  where
    -- TODO: Is there a standard function in Cabal to do this?
    packageFileName :: FilePath
    packageFileName = display pkgId <.> "tar.gz"

    packageMustExist :: Maybe FilePath -> IO FilePath
    packageMustExist (Just fp) = return fp
    packageMustExist Nothing   = throwIO $ InvalidPackageException pkgId

data InvalidPackageException = InvalidPackageException PackageIdentifier
  deriving (Show, Typeable)

instance Exception InvalidPackageException

{-
-- | Download a package to a temporary location
--
-- It is the responsibility of the calling code to move the package from its
-- temporary location to a permanent location (or delete it).
--
-- Maybe through a VerificationError if the package cannot be verified against
-- the previously downloaded metadata. It is up to the calling code to decide
-- what to do with such an exception; in particular, we do NOT automatically
-- renew the root metadata at this point (this matches the TUF spec).
downloadPackage :: Repository -> PackageIdentifier -> IO FilePath
downloadPackage Repository{..} pkgId = do
    undefined
    {-
    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    cachedRoot :: Trusted Root
       <- repGetCachedRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
    let keyEnv = rootKeys (trusted cachedRoot)

    -- Get the metadata (from the previously updated index)
    mTargets :: Maybe (Trusted Targets)
       <- repGetCached (FilePackageMetadata pkgId)
      >>= traverse (readJSON keyEnv)
      >>= return . fmap trustLocalFile

    -- If this is not found, the package is not available
    case mTargets of
      Nothing -> do
        -- TODO: Not sure if we should be throwing an exception here or return
        -- Maybe FilePath. Requesting a non-existing package is a bug.
        throwIO $ userError "Invalid package"
      Just targets -> do
        targetMetaData :: Trusted FileInfo
          <- case trustedTargetsLookup packageFileName targets of
               Nothing  -> throwIO VerificationErrorUnknownTarget
               Just nfo -> return nfo

        -- TODO: should we check if we have a cached package available?
        -- (the spec says no)
        tarGz <- repGetRemote (FilePackage pkgId)

        -- Verify the fileinfo
        tarGzInfo <- fileInfoTargetFile tarGz
        unless (verifyFileInfo targetMetaData tarGzInfo) $
          throwIO VerificationErrorFileInfo

        -- Return the path to the package
        return tarGz
     -}
  where
    -- TODO: Is there a standard function in Cabal to do this?
    packageFileName :: FilePath
    packageFileName = display pkgId <.> "tar.gz"
-}

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
