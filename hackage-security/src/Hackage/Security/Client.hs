{-# LANGUAGE CPP #-}
#if __GLASGOW_HASKELL__ >= 710
{-# LANGUAGE StaticPointers #-}
#endif
-- | Main entry point into the Hackage Security framework for clients
module Hackage.Security.Client (
    -- * Checking for updates
    HasUpdates(..)
  , CheckExpiry(..)
  , checkForUpdates
    -- * Downloading targets
  , downloadPackage
    -- * Bootstrapping
  , requiresBootstrap
  , bootstrap
    -- * Re-exports
  , module Hackage.Security.TUF
  , module Hackage.Security.Key
    -- ** We only a few bits from .Repository
    -- TODO: Maybe this is a sign that these should be in a different module?
  , CustomRecoverableException(..)
  , Repository -- opaque
  , LogMessage(..)
  ) where

import Prelude hiding (log)
import Control.Exception
import Control.Monad
import Control.Monad.Cont
import Control.Monad.Trans.Cont
import Data.Maybe (isNothing)
import Data.Time
import Data.Traversable (for)
import Data.Typeable (Typeable)
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Distribution.Package (PackageIdentifier)

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Formats
import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Trusted
import Hackage.Security.Trusted.TCB
import Hackage.Security.TUF
import Hackage.Security.Util.Path
import Hackage.Security.Util.Stack
import Hackage.Security.Util.Some
import qualified Hackage.Security.Key.Env   as KeyEnv
import qualified Hackage.Security.Util.Lens as Lens

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
checkForUpdates rep checkExpiry =
    withMirror rep $ do
      -- more or less randomly chosen maximum iterations
      -- See <https://github.com/theupdateframework/tuf/issues/287>.
      limitIterations FirstAttempt 5
  where
    -- The spec stipulates that on a verification error we must download new
    -- root information and start over. However, in order to prevent DoS attacks
    -- we limit how often we go round this loop.
    -- See als <https://github.com/theupdateframework/tuf/issues/287>.
    limitIterations :: IsRetry -> Int -> IO HasUpdates
    limitIterations _isRetry 0 = throwIO VerificationErrorLoop
    limitIterations  isRetry n = do
      mNow <- case checkExpiry of
                CheckExpiry     -> Just <$> getCurrentTime
                DontCheckExpiry -> return Nothing

      catches (evalContT (go mNow isRetry)) [
          Handler $ \(ex :: VerificationError) -> do
            -- NOTE: This call to updateRoot is not itself protected by an
            -- exception handler, and may therefore throw a VerificationError.
            -- This is intentional: if we get verification errors during the
            -- update process, _and_ we cannot update the main root info, then
            -- we cannot do anything.
            log rep $ LogVerificationError ex
            updateRoot rep mNow AfterVerificationError (Left ex)
            limitIterations AfterVerificationError (n - 1)
        , Handler $ \RootUpdated -> do
            log rep $ LogRootUpdated
            limitIterations isRetry (n - 1)
        ]

    -- NOTE: Every call to 'getRemote' in 'go' implicitly scopes over the
    -- whole remainder of the function (through the use of ContT). This means
    -- that none of the downloaded files will be cached until the entire check
    -- for updates check completes successfully.
    -- See also <https://github.com/theupdateframework/tuf/issues/283>.
    go :: Maybe UTCTime -> IsRetry -> ContT r IO HasUpdates
    go mNow isRetry = do
      -- We need the cached root information in order to resolve key IDs and
      -- verify signatures
      cachedRoot :: Trusted Root <- do
        cachedPath <- getCachedRoot rep
        signed     <- readJSON (repLayout rep) KeyEnv.empty cachedPath
        return $ trustLocalFile signed
      let keyEnv = rootKeys (trusted cachedRoot)

      -- Get the old timestamp (if any)
      mOldTS :: Maybe (Trusted Timestamp) <- do
        mCachedPath <- getCached rep CachedTimestamp
        for mCachedPath $ \cachedPath -> do
          signed <- readJSON (repLayout rep) keyEnv cachedPath
          return $ trustLocalFile signed

      -- Get the new timestamp
      newTS :: Trusted Timestamp <- do
        (targetPath, tempPath) <- getRemote' rep isRetry RemoteTimestamp
        signed   <- readJSON (repLayout rep) keyEnv tempPath
        verified <- throwErrors $ verifyTimestamp
                      cachedRoot
                      targetPath
                      (fmap (timestampVersion . trusted) mOldTS)
                      mNow
                      signed
        return $ trustVerified verified

      -- Check if the snapshot has changed
      let mOldSnapshotInfo = fmap (static timestampInfoSnapshot <$$>) mOldTS
          newSnapshotInfo  = static timestampInfoSnapshot <$$> newTS
      if not (infoChanged mOldSnapshotInfo newSnapshotInfo)
        then
          return NoUpdates
        else do
          -- Get the old snapshot (if any)
          mOldSS :: Maybe (Trusted Snapshot) <- do
            mCachedPath <- getCached rep CachedSnapshot
            for mCachedPath $ \cachedPath -> do
              signed <- readJSON (repLayout rep) keyEnv cachedPath
              return $ trustLocalFile signed

          -- Get the new snapshot
          let expectedSnapshot =
                RemoteSnapshot (static fileInfoLength <$$> newSnapshotInfo)
          newSS :: Trusted Snapshot <- do
            (targetPath, tempPath) <- getRemote' rep isRetry expectedSnapshot
            verifyFileInfo' (Just newSnapshotInfo) targetPath tempPath
            signed   <- readJSON (repLayout rep) keyEnv tempPath
            verified <- throwErrors $ verifySnapshot
                          cachedRoot
                          targetPath
                          (fmap (snapshotVersion . trusted) mOldSS)
                          mNow
                          signed
            return $ trustVerified verified

          -- If root metadata changed, update and restart
          let mOldRootInfo = fmap (static snapshotInfoRoot <$$>) mOldSS
              newRootInfo  = static snapshotInfoRoot <$$> newSS
          case mOldRootInfo of
            Nothing ->
              -- If we didn't have an old snapshot, consider the root info as
              -- unchanged (otherwise this would loop indefinitely.)
              -- See also <https://github.com/theupdateframework/tuf/issues/286>
              return ()
            Just oldRootInfo ->
              when (not (trustedFileInfoEqual oldRootInfo newRootInfo)) $ liftIO $ do
                updateRoot rep mNow isRetry (Right newRootInfo)
                throwIO RootUpdated

          -- If mirrors changed, download and verify
          let mOldMirrorsInfo = fmap (static snapshotInfoMirrors <$$>) mOldSS
              newMirrorsInfo  = static snapshotInfoMirrors <$$> newSS
              expectedMirrors = RemoteMirrors (static fileInfoLength <$$> newMirrorsInfo)
          when (infoChanged mOldMirrorsInfo newMirrorsInfo) $ do
            -- Get the old mirrors file (so we can verify version numbers)
            mOldMirrors :: Maybe (Trusted Mirrors) <- do
              mCachedPath <- getCached rep CachedMirrors
              for mCachedPath $ \cachedPath -> do
                signed <- readJSON (repLayout rep) keyEnv cachedPath
                return $ trustLocalFile signed

            -- Verify new mirrors
            _newMirrors :: Trusted Mirrors <- do
              (targetPath, tempPath) <- getRemote' rep isRetry expectedMirrors
              verifyFileInfo' (Just newMirrorsInfo) targetPath tempPath
              signed   <- readJSON (repLayout rep) keyEnv tempPath
              verified <- throwErrors $ verifyMirrors
                            cachedRoot
                            targetPath
                            (fmap (mirrorsVersion . trusted) mOldMirrors)
                            mNow
                           signed
              return $ trustVerified verified

            -- We don't actually _do_ anything with the mirrors file now
            -- because we want to use a single server for a single
            -- check-for-updates request. If validation was successful the
            -- repository will have cached the mirrors file and it will
            -- be available on the next request.
            return ()

          -- If the index changed, download it and verify it
          let mOldTarGzInfo = fmap (static snapshotInfoTarGz <$$>) mOldSS
              newTarGzInfo  = static snapshotInfoTarGz <$$> newSS
              mNewTarInfo   = trustSeq (static snapshotInfoTar <$$> newSS)
              expectedIdx   =
                  -- This definition is a bit ugly, not sure how to improve it
                  case mNewTarInfo of
                    Nothing -> Some $ RemoteIndex NonEmpty $
                      FsGz (static fileInfoLength <$$> newTarGzInfo)
                    Just newTarInfo -> Some $ RemoteIndex NonEmpty $
                      FsUnGz (static fileInfoLength <$$> newTarInfo)
                             (static fileInfoLength <$$> newTarGzInfo)
          when (infoChanged mOldTarGzInfo newTarGzInfo) $ do
            (format, targetPath, tempPath) <-
              case expectedIdx of
                Some expectedIdx' -> getRemote rep isRetry expectedIdx'

            -- Check against the appropriate hash, depending on which file the
            -- 'Repository' decided to download. Note that we cannot ask the
            -- repository for the @.tar@ file independent of which file it
            -- decides to download; if it downloads a compressed file, we
            -- don't want to require the 'Repository' to decompress an
            -- unverified file (because a clever attacker could then exploit,
            -- say, buffer overrun in the decompression algorithm).
            case format of
              Some FGz ->
                verifyFileInfo' (Just newTarGzInfo) targetPath tempPath
              Some FUn ->
                -- If the repository returns an uncompressed index but does
                -- not list a corresponding hash we throw an exception
                case mNewTarInfo of
                  Just info -> verifyFileInfo' (Just info) targetPath tempPath
                  Nothing   -> liftIO $ throwIO unexpectedUncompressedTar

          return HasUpdates

    infoChanged :: Maybe (Trusted FileInfo) -> Trusted FileInfo -> Bool
    infoChanged Nothing    _   = True
    infoChanged (Just old) new = not (trustedFileInfoEqual old new)

    -- TODO: Should these be structured types?
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
-- We additionally delete the cached cached snapshot and timestamp. This is
-- necessary for two reasons:
--
-- 1. If during the normal update process we notice that the root info was
--    updated (because the hash of @root.json@ in the new snapshot is different
--    from the old snapshot) we download new root info and start over, without
--    (yet) downloading a (potential) new index. This means it is important that
--    we not overwrite our local cached snapshot, because if we did we would
--    then on the next iteration conclude there were no updates and we would
--    fail to notice that we should have updated the index. However, unless we
--    do something, this means that we would conclude on the next iteration once
--    again that the root info has changed (because the hash in the new shapshot
--    still doesn't match the hash in the cached snapshot), and we would loop
--    until we throw a 'VerificationErrorLoop' exception. By deleting the local
--    snapshot we basically reset the client to its initial state, and we will
--    not try to download the root info once again. The only downside of this is
--    that we will also re-download the index after every root info change.
--    However, this should be infrequent enough that this isn't an issue.
--    See also <https://github.com/theupdateframework/tuf/issues/285>.
--
-- 2. Additionally, deleting the local timestamp and snapshot protects against
--    an attack where an attacker has set the file version of the snapshot or
--    timestamp to MAX_INT, thereby making further updates impossible.
--    (Such an attack would require a timestamp/snapshot key compromise.)
--
-- However, we _ONLY_ do this when the root information has actually changed.
-- If we did this unconditionally it would mean that we delete the locally
-- cached timestamp whenever the version on the remote timestamp is invalid,
-- thereby rendering the file version on the timestamp and the snapshot useless.
-- See <https://github.com/theupdateframework/tuf/issues/283#issuecomment-115739521>
updateRoot :: Repository
           -> Maybe UTCTime
           -> IsRetry
           -> Either VerificationError (Trusted FileInfo)
           -> IO ()
updateRoot rep mNow isRetry eFileInfo = evalContT $ do
    oldRoot :: Trusted Root <- do
      cachedPath <- getCachedRoot rep
      signed     <- readJSON (repLayout rep) KeyEnv.empty cachedPath
      return $ trustLocalFile signed

    let mFileInfo    = eitherToMaybe eFileInfo
        expectedRoot = RemoteRoot (fmap (static fileInfoLength <$$>) mFileInfo)
    newRoot :: Trusted Root <- do
      (targetPath, tempPath) <- getRemote' rep isRetry expectedRoot
      verifyFileInfo' mFileInfo targetPath tempPath
      signed   <- readJSON (repLayout rep) KeyEnv.empty tempPath
      verified <- throwErrors $ verifyRoot oldRoot targetPath mNow signed
      return $ trustVerified verified

    let oldVersion = Lens.get fileVersion (trusted oldRoot)
        newVersion = Lens.get fileVersion (trusted newRoot)
    when (oldVersion /= newVersion) $ clearCache rep

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
downloadPackage :: Repository -> PackageIdentifier -> (TempPath -> IO a) -> IO a
downloadPackage rep pkgId callback = withMirror rep $ evalContT $ do
    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures. Note that whenever we read a JSON file, we verify
    -- signatures (even if we don't verify the keys); if this is a problem
    -- (for performance) we need to parameterize parseJSON.
    cachedRoot :: Trusted Root <- do
      cachedPath <- getCachedRoot rep
      signed     <- readJSON (repLayout rep) KeyEnv.empty cachedPath
      return $ trustLocalFile signed
    let keyEnv = rootKeys (trusted cachedRoot)

    -- NOTE: The files inside the index as evaluated lazily.
    --
    -- 1. The index tarball contains delegated target.json files for both
    --    unsigned and signed packages. We need to verify the signatures of all
    --    signed metadata (that is: the metadata for signed packages).
    --
    -- 2. Since the tarball also contains the .cabal files, we should also
    --    verify the hashes of those .cabal files against the hashes recorded in
    --    signed metadata (there is no point comparing against hashes recorded
    --    in unsigned metadata because attackers could just change those).
    --
    -- Since we don't have author signing yet, we don't have any additional
    -- signed metadata and therefore we currently don't have to do anything
    -- here.
    --
    -- TODO: If we have explicit, author-signed, lists of versions for a package
    -- (as described in @README.md@), then evaluating these "middle-level"
    -- delegation files lazily opens us up to a rollback attack: if we've never
    -- downloaded the delegations for a package before, then we have nothing to
    -- compare the version number in the file that we downloaded against. One
    -- option is to always download and verify all these middle level files
    -- (strictly); other is to include the version number of all of these files
    -- in the snapshot. This is described in more detail in
    -- <https://github.com/theupdateframework/tuf/issues/282#issuecomment-102468421>.
    let trustIndex :: Signed a -> Trusted a
        trustIndex = trustLocalFile

    -- Get the metadata (from the previously updated index)
    --
    -- NOTE: Currently we hardcode the location of the package specific
    -- metadata. By rights we should read the global targets file and apply the
    -- delegation rules. Until we have author signing however this is
    -- unnecessary.
    targets :: Trusted Targets <- do
      mRaw <- getFromIndex rep (IndexPkgMetadata pkgId)
      case mRaw of
        Nothing -> liftIO $ throwIO $ InvalidPackageException pkgId
        Just raw -> do
          signed <- throwErrors $ parseJSON_Keys_NoLayout keyEnv raw
          return $ trustIndex signed

    -- The path of the package, relative to the targets.json file
    let filePath :: TargetPath
        filePath = TargetPathRepo $ repoLayoutPkgTarGz (repLayout rep) pkgId

    let mTargetMetaData :: Maybe (Trusted FileInfo)
        mTargetMetaData = trustSeq
                        $ trustStatic (static targetsLookup)
             `trustApply` DeclareTrusted filePath
             `trustApply` targets
    targetMetaData :: Trusted FileInfo
      <- case mTargetMetaData of
           Nothing -> liftIO $
             throwIO $ VerificationErrorUnknownTarget filePath
           Just nfo ->
             return nfo

    -- TODO: should we check if cached package available? (spec says no)
    let expectedPkg = RemotePkgTarGz pkgId (static fileInfoLength <$$> targetMetaData)
    tarGz <- do
      (targetPath, tempPath) <- getRemote' rep FirstAttempt expectedPkg
      verifyFileInfo' (Just targetMetaData) targetPath tempPath
      return tempPath
    lift $ callback tarGz

data InvalidPackageException = InvalidPackageException PackageIdentifier
  deriving (Show, Typeable)

instance Exception InvalidPackageException

{-------------------------------------------------------------------------------
  Bootstrapping
-------------------------------------------------------------------------------}

-- | Check if we need to bootstrap (i.e., if we have root info)
requiresBootstrap :: Repository -> IO Bool
requiresBootstrap rep = isNothing <$> repGetCached rep CachedRoot

-- | Bootstrap the chain of trust
--
-- New clients might need to obtain a copy of the root metadata. This however
-- represents a chicken-and-egg problem: how can we verify the root metadata
-- we downloaded? The only possibility is to be provided with a set of an
-- out-of-band set of root keys and an appropriate threshold.
--
-- Clients who provide a threshold of 0 can do an initial "unsafe" update
-- of the root information, if they wish.
--
-- The downloaded root information will _only_ be verified against the
-- provided keys, and _not_ against previously downloaded root info (if any).
-- It is the responsibility of the client to call `bootstrap` only when this
-- is the desired behaviour.
bootstrap :: Repository -> [KeyId] -> KeyThreshold -> IO ()
bootstrap rep trustedRootKeys keyThreshold = withMirror rep $ evalContT $ do
    _newRoot :: Trusted Root <- do
      (targetPath, tempPath) <- getRemote' rep FirstAttempt (RemoteRoot Nothing)
      signed   <- readJSON (repLayout rep) KeyEnv.empty tempPath
      verified <- throwErrors $ verifyFingerprints
                    trustedRootKeys
                    keyThreshold
                    targetPath
                    signed
      return $ trustVerified verified

    clearCache rep

{-------------------------------------------------------------------------------
  Wrapper around the Repository functions (to avoid callback hell)
-------------------------------------------------------------------------------}

getRemote :: forall fs r.
             Repository
          -> IsRetry
          -> RemoteFile fs
          -> ContT r IO (Some Format, TargetPath, TempPath)
getRemote r isRetry file = ContT aux
  where
    aux :: ((Some Format, TargetPath, TempPath) -> IO r) -> IO r
    aux k = repWithRemote r isRetry file (wrapK k)

    wrapK :: ((Some Format, TargetPath, TempPath) -> IO r)
          -> (SelectedFormat fs -> TempPath -> IO r)
    wrapK k format tempPath =
        k (selectedFormatSome format, targetPath, tempPath)
      where
        targetPath :: TargetPath
        targetPath = TargetPathRepo $ remoteRepoPath' (repLayout r) file format

-- | Variation on getRemote where we only expect one type of result
getRemote' :: forall f r.
              Repository
           -> IsRetry
           -> RemoteFile (f :- ())
           -> ContT r IO (TargetPath, TempPath)
getRemote' r isRetry file = ignoreFormat <$> getRemote r isRetry file
  where
    ignoreFormat (_format, targetPath, tempPath) = (targetPath, tempPath)

getCached :: MonadIO m => Repository -> CachedFile -> m (Maybe AbsolutePath)
getCached r file = liftIO $ repGetCached r file

getCachedRoot :: MonadIO m => Repository -> m AbsolutePath
getCachedRoot r = liftIO $ repGetCachedRoot r

clearCache :: MonadIO m => Repository -> m ()
clearCache r = liftIO $ repClearCache r

log :: MonadIO m => Repository -> LogMessage -> m ()
log r msg = liftIO $ repLog r msg

-- We translate to a lazy bytestring here for convenience
getFromIndex :: MonadIO m
             => Repository
             -> IndexFile
             -> m (Maybe BS.L.ByteString)
getFromIndex r file = liftIO $
    fmap tr <$> repGetFromIndex r file
  where
    tr :: BS.ByteString -> BS.L.ByteString
    tr = BS.L.fromChunks . (:[])

-- Tries to load the cached mirrors file
withMirror :: Repository -> IO a -> IO a
withMirror rep callback = do
    mMirrors <- repGetCached rep CachedMirrors
    mirrors  <- case mMirrors of
      Nothing -> return Nothing
      Just fp -> filterMirrors <$> (throwErrors =<< readJSON_NoKeys_NoLayout fp)
    repWithMirror rep mirrors $ callback
  where
    filterMirrors :: UninterpretedSignatures Mirrors -> Maybe [Mirror]
    filterMirrors = Just
                  . filter (canUseMirror . mirrorContent)
                  . mirrorsMirrors
                  . uninterpretedSigned

    -- Once we add support for partial mirrors, we wil need an additional
    -- argument to 'repWithMirror' (here, not in the Repository API itself)
    -- that tells us which files we will be requested from the mirror.
    -- We can then compare that against the specification of the partial mirror
    -- to see if all of those files are available from this mirror.
    canUseMirror :: MirrorContent -> Bool
    canUseMirror MirrorFull = True

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Local files are assumed trusted
--
-- There is no point tracking chain of trust for local files because that chain
-- would necessarily have to start at an implicitly trusted (though unverified)
-- file: the root metadata.
trustLocalFile :: Signed a -> Trusted a
trustLocalFile Signed{..} = DeclareTrusted signed

-- | Just a simple wrapper around 'verifyFileInfo'
--
-- Throws a VerificationError if verification failed.
verifyFileInfo' :: MonadIO m
                => Maybe (Trusted FileInfo)
                -> TargetPath  -- ^ For error messages
                -> TempPath    -- ^ File to verify
                -> m ()
verifyFileInfo' Nothing     _          _        = return ()
verifyFileInfo' (Just info) targetPath tempPath = liftIO $ do
    verified <- verifyFileInfo tempPath info
    unless verified $ throw $ VerificationErrorFileInfo targetPath

readJSON :: (MonadIO m, FromJSON ReadJSON_Keys_Layout a)
         => RepoLayout -> KeyEnv -> TempPath -> m a
readJSON repoLayout keyEnv fpath = liftIO $ do
    result <- readJSON_Keys_Layout keyEnv repoLayout fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

throwErrors :: (MonadIO m, Exception e) => Either e a -> m a
throwErrors (Left err) = liftIO $ throwIO err
throwErrors (Right a)  = return a

eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe (Left  _) = Nothing
eitherToMaybe (Right b) = Just b
