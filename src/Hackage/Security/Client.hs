module Hackage.Security.Client (
    -- * Checking for updates
    HasUpdates(..)
  , CheckExpiry(..)
  , checkForUpdates
    -- * Downloading targets
  , downloadPackage
  ) where

import Control.Exception
import Control.Monad
import Data.Time
import Data.Typeable (Typeable)
import System.FilePath

import Distribution.Package (PackageIdentifier)
import Distribution.Text

import Hackage.Security.Client.Repository
import Hackage.Security.JSON
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF
import qualified Hackage.Security.Key.Env as KeyEnv

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
  deriving Show

data HasUpdates = HasUpdates | NoUpdates
  deriving Show

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
        Handler $ \(ex :: VerificationError) -> do
          -- NOTE: This call to updateRoot is not itself protected by an
          -- exception handler, and may therefore throw a VerificationError.
          -- This is intentional: if we get verification errors during the
          -- update process, _and_ we cannot update the main root info, then
          -- we cannot do anything.
          putStrLn $ "Warning: verification error: " ++ show ex
          updateRoot rep mNow (Left ex)
          checkForUpdates rep checkExpiry
      , Handler $ \RootUpdated -> do
          putStrLn $ "Notice: root updated"
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
      let mOldSnapshotInfo = fmap trustedTimestampInfoSnapshot mOldTS
          newSnapshotInfo  = trustedTimestampInfoSnapshot newTS
      if not (infoChanged mOldSnapshotInfo newSnapshotInfo)
        then
          return NoUpdates
        else do
          -- Get the old snapshot (if any)
          mOldSS :: Maybe (Trusted Snapshot)
             <- repGetCached (FileSnapshot ())
            >>= traverse (readJSON keyEnv)
            >>= return . fmap trustLocalFile

          -- Get the new snapshot
          let expectedSnapshot =
                FileSnapshot (trustedFileInfoLength newSnapshotInfo)
          newSS :: Trusted Snapshot
             <- repWithRemote expectedSnapshot
                    $ verifyFileInfo' (Just newSnapshotInfo)
                  >=> readJSON keyEnv
                  >=> throwErrors . verifySnapshot
                        cachedRoot
                        (fmap fileVersion mOldSS)
                        mNow

          -- If root metadata changed, update and restart
          let mOldRootInfo = fmap trustedSnapshotInfoRoot mOldSS
              newRootInfo  = trustedSnapshotInfoRoot newSS
          when (infoChanged mOldRootInfo newRootInfo) $ do
            updateRoot rep mNow (Right newRootInfo)
            throwIO RootUpdated

          -- If the index changed, download it and verify it
          let mOldTarGzInfo = fmap trustedSnapshotInfoTarGz mOldSS
              newTarGzInfo  = trustedSnapshotInfoTarGz newSS
              mNewTarInfo   = trustedSnapshotInfoTar   newSS
              expectedIndex = FileIndex {
                  fileIndexTarGzInfo = trustedFileInfoLength newTarGzInfo
                , fileIndexTarInfo   = fmap trustedFileInfoLength mNewTarInfo
                }
          when (infoChanged mOldTarGzInfo newTarGzInfo) $
            repWithRemote expectedIndex $ \indexPath -> do
              -- Check against the appropriate hash, depending on which file the
              -- 'Repository' decided to download. Note that we cannot ask the
              -- repository for the @.tar@ file independent of which file it
              -- decides to download; if it downloads a compressed file, we
              -- don't want to require the 'Repository' to decompress an
              -- unverified file (because a clever attacker could then exploit,
              -- say, buffer overrun in the decompression algorithm).
              let (_, indexExt) = splitExtension indexPath
              void $ case indexExt of
                ".gz" ->
                  verifyFileInfo' (Just newTarGzInfo) indexPath
                ".tar" ->
                  -- If the repository returns an uncompressed index but does
                  -- not list a corresponding hash we throw an exception
                  case mNewTarInfo of
                    Just info -> verifyFileInfo' (Just info) indexPath
                    Nothing   -> throwIO unexpectedUncompressedTar
                _otherwise ->
                  throwIO unexpectedIndexFormat

          -- Since we regard all local files as trusted, strictly speaking we
          -- should now verify the contents of the index tarball.
          -- This means check two things:
          --
          -- 1. The index tarball contains delegated target.json files for
          --    both unsigned and signed packages. We need to the signatures of
          --    all signed metadata (that is: the metadata for signed packages).
          --
          -- 2. Since the tarball also contains the .cabal files, we should also
          --    verify the hashes of those .cabal files against the hashes
          --    recorded in signed metadata (there is no point comparing against
          --    hashes recorded in unsigned metadata because attackers could
          --    just change those).
          --
          -- Since we don't have author signing yet, we don't have any
          -- additional signed metadata and therefore we currently don't have
          -- to do anything here.
          --
          -- TODO: One question is whether we should regard the checkForUpdates
          -- to have failed if one specific package metadata fails to verify.
          -- See also <https://github.com/theupdateframework/tuf/issues/282>.

          putStrLn "There are updates!!"
          return HasUpdates

    infoChanged :: Maybe (Trusted FileInfo) -> Trusted FileInfo -> Bool
    infoChanged Nothing    _   = True
    infoChanged (Just old) new = old /= new

    -- TODO: Should these be structured types?
    unexpectedIndexFormat     = userError "Unexpected index format"
    unexpectedUncompressedTar = userError "Unexpected uncompressed tarball"

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
--
-- We don't always have root file information available. If we notice during
-- the normal update process that the root information has changed then the
-- snapshot will give us the new file information; but if we need to update
-- the root information due to a verification error we do not.
--
-- If there was a verification error we additionally delete the cached
-- snapshot and timestamp.
updateRoot :: Repository
           -> Maybe UTCTime
           -> Either VerificationError (Trusted FileInfo)
           -> IO ()
updateRoot Repository{..} mNow eFileInfo = do
    oldRoot :: Trusted Root
       <- repGetCachedRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile

    let mFileInfo    = eitherToMaybe eFileInfo
        expectedRoot = FileRoot (fmap trustedFileInfoLength mFileInfo)
    _newRoot :: Trusted Root
       <- repWithRemote expectedRoot
              $ verifyFileInfo' mFileInfo
            >=> readJSON KeyEnv.empty
            >=> throwErrors . verifyRoot oldRoot mNow

    case eFileInfo of
      Left _err -> do
        repDeleteCached $ FileTimestamp
        repDeleteCached $ FileSnapshot ()
      Right _info ->
        return ()

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
--   renew the root metadata at this point.
--   (See also <https://github.com/theupdateframework/tuf/issues/281>.)
-- * May throw an InvalidPackageException if the requested package does not
--   exist (this is a programmer error).
downloadPackage :: Repository -> PackageIdentifier -> (TemporaryPath -> IO a) -> IO a
downloadPackage Repository{..} pkgId callback = do
    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    -- redundant signature verification
    -- local information implicitly trusted becuse starts from implicitly trusted root info
    cachedRoot :: Trusted Root
       <- repGetCachedRoot
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
    let keyEnv = rootKeys (trusted cachedRoot)

    -- Get the metadata (from the previously updated index)
    targets :: Trusted Targets
       <- repGetCached (FilePkgMeta pkgId)
      >>= packageMustExist
      >>= readJSON keyEnv
      >>= return . trustLocalFile

    targetMetaData :: Trusted FileInfo
      <- case trustedTargetsLookup packageFileName targets of
           Nothing  -> throwIO VerificationErrorUnknownTarget
           Just nfo -> return nfo

    -- TODO: should we check if cached package available? (spec says no)
    let expectedPkg = FilePkgTarGz pkgId (trustedFileInfoLength targetMetaData)
    repWithRemote expectedPkg $ \tarGz -> do
      callback =<< verifyFileInfo' (Just targetMetaData) tarGz
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

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Local files are assumed trusted
trustLocalFile :: Signed a -> Trusted a
trustLocalFile Signed{..} = DeclareTrusted signed

-- | Just a simple wrapper around 'verifyFileInfo'
--
-- Throws a VerificationError if verification failed. For convenience in
-- composition returns the argument FilePath otherwise.
verifyFileInfo' :: Maybe (Trusted FileInfo) -> FilePath -> IO FilePath
verifyFileInfo' Nothing     fp = return fp
verifyFileInfo' (Just info) fp = do
    verified <- verifyFileInfo fp info
    unless verified $ throw VerificationErrorFileInfo
    return fp

readJSON :: FromJSON ReadJSON a => KeyEnv -> FilePath -> IO a
readJSON keyEnv fpath = do
    result <- readCanonical keyEnv fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

throwErrors :: Exception e => Either e a -> IO a
throwErrors (Left err) = throwIO err
throwErrors (Right a)  = return a

eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe (Left  _) = Nothing
eitherToMaybe (Right b) = Just b
