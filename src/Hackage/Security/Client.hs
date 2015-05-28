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
import Control.Monad.Cont
import Control.Monad.Trans.Cont
import Data.Time
import Data.Typeable (Typeable)
import System.FilePath
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Distribution.Package (PackageIdentifier)
import Distribution.Text

import Hackage.Security.Client.Repository (Repository)
import Hackage.Security.Client.Repository hiding (Repository(..))
import Hackage.Security.Client.Formats
import Hackage.Security.JSON
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF
import Hackage.Security.Util.Stack
import Hackage.Security.Util.Some
import qualified Hackage.Security.Key.Env as KeyEnv
import qualified Hackage.Security.Client.Repository as Repository

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
    repWithMirror rep $ do
      -- more or less randomly chosen maximum iterations
      -- See <https://github.com/theupdateframework/tuf/issues/287>.
      limitIterations 5
  where
    -- The spec stipulates that on a verification error we must download new
    -- root information and start over. However, in order to prevent DoS attacks
    -- we limit how often we go round this loop.
    limitIterations :: Int -> IO HasUpdates
    limitIterations 0 = throwIO VerificationErrorLoop
    limitIterations n = do
      mNow <- case checkExpiry of
                CheckExpiry     -> Just <$> getCurrentTime
                DontCheckExpiry -> return Nothing

      catches (evalContT (go mNow)) [
          Handler $ \(ex :: VerificationError) -> do
            -- NOTE: This call to updateRoot is not itself protected by an
            -- exception handler, and may therefore throw a VerificationError.
            -- This is intentional: if we get verification errors during the
            -- update process, _and_ we cannot update the main root info, then
            -- we cannot do anything.
            repLog rep $ LogVerificationError ex
            updateRoot rep mNow (Left ex)
            limitIterations (n - 1)
        , Handler $ \RootUpdated -> do
            repLog rep $ LogRootUpdated
            limitIterations (n - 1)
        ]

    -- NOTE: Every call to 'repGetRemote' in 'go' implicitly scopes over the
    -- whole remainder of the function (through the use of ContT). This means
    -- that none of the downloaded files will be cached until the entire check
    -- for updates check completes successfully.
    -- See also <https://github.com/theupdateframework/tuf/issues/283>.
    go :: Maybe UTCTime -> ContT r IO HasUpdates
    go mNow = do
      -- We need the cached root information in order to resolve key IDs and
      -- verify signatures
      cachedRoot :: Trusted Root
         <- repGetCachedRoot rep
        >>= readJSON KeyEnv.empty
        >>= return . trustLocalFile
      let keyEnv = rootKeys (trusted cachedRoot)

      -- Get the old timestamp (if any)
      mOldTS :: Maybe (Trusted Timestamp)
         <- repGetCached rep CachedTimestamp
        >>= traverse (readJSON keyEnv)
        >>= return . fmap trustLocalFile

      -- Get the new timestamp
      newTS :: Trusted Timestamp
         <- repGetRemote' rep RemoteTimestamp
        >>= readJSON keyEnv
        >>= throwErrors . verifyTimestamp
              cachedRoot
              (fmap (timestampVersion . trusted) mOldTS)
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
             <- repGetCached rep CachedSnapshot
            >>= traverse (readJSON keyEnv)
            >>= return . fmap trustLocalFile

          -- Get the new snapshot
          let expectedSnapshot =
                RemoteSnapshot (trustedFileInfoLength newSnapshotInfo)
          newSS :: Trusted Snapshot
             <- repGetRemote' rep expectedSnapshot
            >>= verifyFileInfo' (Just newSnapshotInfo)
            >>= readJSON keyEnv
            >>= throwErrors . verifySnapshot
                  cachedRoot
                  (fmap (snapshotVersion . trusted) mOldSS)
                  mNow

          -- If root metadata changed, update and restart
          let newRootInfo = trustedSnapshotInfoRoot newSS
          case fmap trustedSnapshotInfoRoot mOldSS of
            Nothing ->
              -- If we didn't have an old snapshot, consider the root info as
              -- unchanged (otherwise this would loop indefinitely.)
              -- See also <https://github.com/theupdateframework/tuf/issues/286>
              return ()
            Just oldRootInfo ->
              when (infoChanged (Just oldRootInfo) newRootInfo) $ liftIO $ do
                updateRoot rep mNow (Right newRootInfo)
                throwIO RootUpdated

          -- If the index changed, download it and verify it
          let mOldTarGzInfo = fmap trustedSnapshotInfoTarGz mOldSS
              newTarGzInfo  = trustedSnapshotInfoTarGz newSS
              mNewTarInfo   = trustedSnapshotInfoTar   newSS
              expectedIndex =
                  -- This definition is a bit ugly, not sure how to improve it
                  case mNewTarInfo of
                    Nothing -> Some $ RemoteIndex NonEmpty $
                      FsGz (trustedFileInfoLength newTarGzInfo)
                    Just newTarInfo -> Some $ RemoteIndex NonEmpty $
                      FsUnGz (trustedFileInfoLength newTarInfo)
                             (trustedFileInfoLength newTarGzInfo)
          when (infoChanged mOldTarGzInfo newTarGzInfo) $ do
            (indexFormat, indexPath) <- repGetRemote rep expectedIndex

            -- Check against the appropriate hash, depending on which file the
            -- 'Repository' decided to download. Note that we cannot ask the
            -- repository for the @.tar@ file independent of which file it
            -- decides to download; if it downloads a compressed file, we
            -- don't want to require the 'Repository' to decompress an
            -- unverified file (because a clever attacker could then exploit,
            -- say, buffer overrun in the decompression algorithm).
            case indexFormat of
              Some FGz ->
                void $ verifyFileInfo' (Just newTarGzInfo) indexPath
              Some FUn ->
                -- If the repository returns an uncompressed index but does
                -- not list a corresponding hash we throw an exception
                case mNewTarInfo of
                  Just info -> void $ verifyFileInfo' (Just info) indexPath
                  Nothing   -> liftIO $ throwIO unexpectedUncompressedTar

          return HasUpdates

    infoChanged :: Maybe (Trusted FileInfo) -> Trusted FileInfo -> Bool
    infoChanged Nothing    _   = True
    infoChanged (Just old) new = old /= new

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
updateRoot :: Repository
           -> Maybe UTCTime
           -> Either VerificationError (Trusted FileInfo)
           -> IO ()
updateRoot rep mNow eFileInfo = evalContT $ do
    oldRoot :: Trusted Root
       <- repGetCachedRoot rep
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile

    let mFileInfo    = eitherToMaybe eFileInfo
        expectedRoot = RemoteRoot (fmap trustedFileInfoLength mFileInfo)
    _newRoot :: Trusted Root
       <- repGetRemote' rep expectedRoot
      >>= verifyFileInfo' mFileInfo
      >>= readJSON KeyEnv.empty
      >>= throwErrors . verifyRoot oldRoot mNow

    repClearCache rep

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
downloadPackage rep pkgId callback = repWithMirror rep $ evalContT $ do
    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures. Note that whenever we read a JSON file, we verify
    -- signatures (even if we don't verify the keys); if this is a problem
    -- (for performance) we need to parameterize parseJSON.
    cachedRoot :: Trusted Root
       <- repGetCachedRoot rep
      >>= readJSON KeyEnv.empty
      >>= return . trustLocalFile
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
    -- TODO: If we have explicit, author-signed, ists of versions for a package
    -- (as described in @README.md@), then evaluating these "middle-level"
    -- delegation files lazily opens us up to a rollback attack: if we've never
    -- downloaded the delegations for a package before, then we have nothing to
    -- compare the version number in the file that we downloaded against. One
    -- option is to always download and verify all these middle level files
    -- (strictly); other is to include the version number of all of these files
    -- in the snapshot. This is described in more detail in
    -- <https://github.com/theupdateframework/tuf/issues/282#issuecomment-102468421>.
    let trustIndex = trustLocalFile

    -- Get the metadata (from the previously updated index)
    --
    -- NOTE: Currently we hardcode the location of the package specific
    -- @targets.json@. By rights we should read the global targets file and
    -- apply the delegation rules. Until we have author signing however this
    -- is unnecessary.
    targets :: Trusted Targets
       <- repGetFromIndex rep (IndexPkgMetadata pkgId)
      >>= packageMustExist
      >>= throwErrors . parseJSON keyEnv
      >>= return . trustIndex

    targetMetaData :: Trusted FileInfo
      <- case trustedTargetsLookup packageFileName targets of
           Nothing -> liftIO $
             throwIO $ VerificationErrorUnknownTarget packageFileName
           Just nfo ->
             return nfo

    -- TODO: should we check if cached package available? (spec says no)
    let expectedPkg = RemotePkgTarGz pkgId (trustedFileInfoLength targetMetaData)
    tarGz <- repGetRemote' rep expectedPkg
         >>= verifyFileInfo' (Just targetMetaData)
    lift $ callback tarGz
  where
    -- TODO: Is there a standard function in Cabal to do this?
    packageFileName :: FilePath
    packageFileName = display pkgId <.> "tar.gz"

    packageMustExist :: MonadIO m => Maybe a -> m a
    packageMustExist (Just fp) = return fp
    packageMustExist Nothing   = liftIO $ throwIO $ InvalidPackageException pkgId

data InvalidPackageException = InvalidPackageException PackageIdentifier
  deriving (Show, Typeable)

instance Exception InvalidPackageException

{-------------------------------------------------------------------------------
  Wrapper around the Repository functions (to avoid callback hell)
-------------------------------------------------------------------------------}

repGetRemote :: Repository -> Some RemoteFile -> ContT r IO (Some Format, TempPath)
repGetRemote r (Some file) = ContT aux
  where
    aux :: ((Some Format, TempPath) -> IO r) -> IO r
    aux k = Repository.repWithRemote r file (wrapK k)

    wrapK :: ((Some Format, TempPath) -> IO r)
          -> (SelectedFormat fs -> TempPath -> IO r)
    wrapK k format tempPath = k (selectedFormatSome format, tempPath)

-- | Variation on repGetRemote where we only expect one type of result
repGetRemote' :: Repository -> RemoteFile (f :- ()) -> ContT r IO TempPath
repGetRemote' r file = ContT aux
  where
    aux :: (TempPath -> IO r) -> IO r
    aux k = Repository.repWithRemote r file (wrapK k)

    wrapK :: (TempPath -> IO r)
          -> (SelectedFormat fs -> TempPath -> IO r)
    wrapK k _format tempPath = k tempPath

repGetCached :: MonadIO m => Repository -> CachedFile -> m (Maybe FilePath)
repGetCached r file = liftIO $ Repository.repGetCached r file

repGetCachedRoot :: MonadIO m => Repository -> m FilePath
repGetCachedRoot r = liftIO $ Repository.repGetCachedRoot r

repClearCache :: MonadIO m => Repository -> m ()
repClearCache r = liftIO $ Repository.repClearCache r

repLog :: MonadIO m => Repository -> LogMessage -> m ()
repLog r msg = liftIO $ Repository.repLog r msg

-- We translate to a lazy bytestring here for convenience
repGetFromIndex :: MonadIO m
                => Repository
                -> IndexFile
                -> m (Maybe BS.L.ByteString)
repGetFromIndex r file = liftIO $
    fmap tr <$> Repository.repGetFromIndex r file
  where
    tr :: BS.ByteString -> BS.L.ByteString
    tr = BS.L.fromChunks . (:[])

-- Tries to load the cached mirrors file
repWithMirror :: Repository -> IO a -> IO a
repWithMirror rep callback = do
    mMirrors <- repGetCached rep CachedMirrors
    mirrors  <- case mMirrors of
      Nothing -> return Nothing
      Just fp -> filterMirrors <$> (throwErrors =<< readNoKeys fp)
    Repository.repWithMirror rep mirrors $ callback
  where
    filterMirrors :: IgnoreSigned Mirrors -> Maybe [Mirror]
    filterMirrors = Just
                  . filter (canUseMirror . mirrorContent)
                  . mirrorsMirrors
                  . ignoreSigned

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
-- Throws a VerificationError if verification failed. For convenience in
-- composition returns the argument FilePath otherwise.
verifyFileInfo' :: MonadIO m => Maybe (Trusted FileInfo) -> FilePath -> m FilePath
verifyFileInfo' Nothing     fp = return fp
verifyFileInfo' (Just info) fp = liftIO $ do
    verified <- verifyFileInfo fp info
    unless verified $ throw $ VerificationErrorFileInfo fp
    return fp

readJSON :: (MonadIO m, FromJSON ReadJSON a) => KeyEnv -> FilePath -> m a
readJSON keyEnv fpath = liftIO $ do
    result <- readCanonical keyEnv fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

throwErrors :: (MonadIO m, Exception e) => Either e a -> m a
throwErrors (Left err) = liftIO $ throwIO err
throwErrors (Right a)  = return a

eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe (Left  _) = Nothing
eitherToMaybe (Right b) = Just b
