{-# LANGUAGE CPP #-}
-- | An implementation of Repository that talks to repositories over HTTP.
--
-- This implementation is itself parameterized over a 'HttpClient', so that it
-- it not tied to a specific library; for instance, 'HttpClient' can be
-- implemented with the @HTTP@ library, the @http-client@ libary, or others.
--
-- It would also be possible to give _other_ Repository implementations that
-- talk to repositories over HTTP, if you want to make other design decisions
-- than we did here, in particular:
--
-- * We attempt to do incremental downloads of the index when possible.
-- * We reuse the "Repository.Local"  to deal with the local cache.
-- * We download @timestamp.json@ and @snapshot.json@ together. This is
--   implemented here because:
--   - One level down (HttpClient) we have no access to the local cache
--   - One level up (Repository API) would require _all_ Repositories to
--     implement this optimization.
module Hackage.Security.Client.Repository.Remote (
    -- * Top-level API
    withRepository
  , RepoOpts(..)
  , defaultRepoOpts
  , RemoteTemp
     -- * File sizes
  , FileSize(..)
  , fileSizeWithinBounds
  ) where

import Control.Concurrent
import Control.Exception
import Control.Monad.Cont
import Data.List (nub, intercalate)
import Data.Typeable
import Network.URI hiding (uriPath, path)
import System.IO ()
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Cache (Cache)
import Hackage.Security.Client.Repository.HttpLib
import Hackage.Security.Client.Verify
import Hackage.Security.Trusted
import Hackage.Security.TUF
import Hackage.Security.Util.Checked
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some
import Hackage.Security.Util.Exit
import qualified Hackage.Security.Client.Repository.Cache as Cache

{-------------------------------------------------------------------------------
  Server capabilities
-------------------------------------------------------------------------------}

-- | Server capabilities
--
-- As the library interacts with the server and receives replies, we may
-- discover more information about the server's capabilities; for instance,
-- we may discover that it supports incremental downloads.
newtype ServerCapabilities = SC (MVar ServerCapabilities_)

-- | Internal type recording the various server capabilities we support
data ServerCapabilities_ = ServerCapabilities {
      -- | Does the server support range requests?
      serverAcceptRangesBytes :: Bool
    }

newServerCapabilities :: IO ServerCapabilities
newServerCapabilities = SC <$> newMVar ServerCapabilities {
      serverAcceptRangesBytes      = False
    }

updateServerCapabilities :: ServerCapabilities -> [HttpResponseHeader] -> IO ()
updateServerCapabilities (SC mv) responseHeaders = modifyMVar_ mv $ \caps ->
    return $ caps {
        serverAcceptRangesBytes = serverAcceptRangesBytes caps
          || HttpResponseAcceptRangesBytes `elem` responseHeaders
      }

checkServerCapability :: MonadIO m
                      => ServerCapabilities -> (ServerCapabilities_ -> a) -> m a
checkServerCapability (SC mv) f = liftIO $ withMVar mv $ return . f

{-------------------------------------------------------------------------------
  File size
-------------------------------------------------------------------------------}

data FileSize =
    -- | For most files we download we know the exact size beforehand
    -- (because this information comes from the snapshot or delegated info)
    FileSizeExact Int54

    -- | For some files we might not know the size beforehand, but we might
    -- be able to provide an upper bound (timestamp, root info)
  | FileSizeBound Int54
  deriving Show

fileSizeWithinBounds :: Int54 -> FileSize -> Bool
fileSizeWithinBounds sz (FileSizeExact sz') = sz <= sz'
fileSizeWithinBounds sz (FileSizeBound sz') = sz <= sz'

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

-- | Repository options with a reasonable default
--
-- Clients should use 'defaultRepositoryOpts' and override required settings.
data RepoOpts = RepoOpts {
      -- | Allow additional mirrors?
      --
      -- If this is set to True (default), in addition to the (out-of-band)
      -- specified mirrors we will also use mirrors reported by those
      -- out-of-band mirrors (that is, @mirrors.json@).
      repoAllowAdditionalMirrors :: Bool
    }

-- | Default repository options
defaultRepoOpts :: RepoOpts
defaultRepoOpts = RepoOpts {
      repoAllowAdditionalMirrors = True
    }

-- | Initialize the repository (and cleanup resources afterwards)
--
-- We allow to specify multiple mirrors to initialize the repository. These
-- are mirrors that can be found "out of band" (out of the scope of the TUF
-- protocol), for example in a @cabal.config@ file. The TUF protocol itself
-- will specify that any of these mirrors can serve a @mirrors.json@ file
-- that itself contains mirrors; we consider these as _additional_ mirrors
-- to the ones that are passed here.
--
-- NOTE: The list of mirrors should be non-empty (and should typically include
-- the primary server).
--
-- TODO: In the future we could allow finer control over precisely which
-- mirrors we use (which combination of the mirrors that are passed as arguments
-- here and the mirrors that we get from @mirrors.json@) as well as indicating
-- mirror preferences.
withRepository
  :: HttpLib                          -- ^ Implementation of the HTTP protocol
  -> [URI]                            -- ^ "Out of band" list of mirrors
  -> RepoOpts                         -- ^ Repository options
  -> Cache                            -- ^ Location of local cache
  -> RepoLayout                       -- ^ Repository layout
  -> IndexLayout                      -- ^ Index layout
  -> (LogMessage -> IO ())            -- ^ Logger
  -> (Repository RemoteTemp -> IO a)  -- ^ Callback
  -> IO a
withRepository httpLib
               outOfBandMirrors
               repoOpts
               cache
               repLayout
               repIndexLayout
               logger
               callback
               = do
    selectedMirror <- newMVar Nothing
    caps <- newServerCapabilities
    let remoteConfig mirror = RemoteConfig {
                                  cfgLayout   = repLayout
                                , cfgHttpLib  = httpLib
                                , cfgBase     = mirror
                                , cfgCache    = cache
                                , cfgCaps     = caps
                                , cfgLogger   = liftIO . logger
                                , cfgOpts     = repoOpts
                                }
    callback Repository {
        repGetRemote     = getRemote remoteConfig selectedMirror
      , repGetCached     = Cache.getCached     cache
      , repGetCachedRoot = Cache.getCachedRoot cache
      , repClearCache    = Cache.clearCache    cache
      , repWithIndex     = Cache.withIndex     cache
      , repGetIndexIdx   = Cache.getIndexIdx   cache
      , repLockCache     = Cache.lockCacheWithLogger logger cache
      , repWithMirror    = withMirror httpLib
                                      selectedMirror
                                      logger
                                      outOfBandMirrors
                                      repoOpts
      , repLog           = logger
      , repLayout        = repLayout
      , repIndexLayout   = repIndexLayout
      , repDescription   = "Remote repository at " ++ show outOfBandMirrors
      }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | We select a mirror in 'withMirror' (the implementation of 'repWithMirror').
-- Outside the scope of 'withMirror' no mirror is selected, and a call to
-- 'getRemote' will throw an exception. If this exception is ever thrown its
-- a bug: calls to 'getRemote' ('repGetRemote') should _always_ be in the
-- scope of 'repWithMirror'.
type SelectedMirror = MVar (Maybe URI)

-- | Get the selected mirror
--
-- Throws an exception if no mirror was selected (this would be a bug in the
-- client code).
--
-- NOTE: Cannot use 'withMVar' here, because the callback would be inside the
-- scope of the withMVar, and there might be further calls to 'withRemote' made
-- by the callback argument to 'withRemote', leading to deadlock.
getSelectedMirror :: SelectedMirror -> IO URI
getSelectedMirror selectedMirror = do
     mBaseURI <- readMVar selectedMirror
     case mBaseURI of
       Nothing      -> internalError "Internal error: no mirror selected"
       Just baseURI -> return baseURI

-- | Get a file from the server
getRemote :: Throws SomeRemoteError
          => (URI -> RemoteConfig)
          -> SelectedMirror
          -> AttemptNr
          -> RemoteFile fs typ
          -> Verify (Some (HasFormat fs), RemoteTemp typ)
getRemote remoteConfig selectedMirror attemptNr remoteFile = do
    baseURI <- liftIO $ getSelectedMirror selectedMirror
    let cfg = remoteConfig baseURI
    downloadMethod <- liftIO $ pickDownloadMethod cfg attemptNr remoteFile
    getFile cfg attemptNr remoteFile downloadMethod

-- | HTTP options
--
-- We want to make sure caches don't transform files in any way (as this will
-- mess things up with respect to hashes etc). Additionally, after a validation
-- error we want to make sure caches get files upstream in case the validation
-- error was because the cache updated files out of order.
httpRequestHeaders :: RemoteConfig -> AttemptNr -> [HttpRequestHeader]
httpRequestHeaders RemoteConfig{..} attemptNr =
    if attemptNr == 0 then defaultHeaders
                      else HttpRequestMaxAge0 : defaultHeaders
  where
    -- Headers we provide for _every_ attempt, first or not
    defaultHeaders :: [HttpRequestHeader]
    defaultHeaders = [HttpRequestNoTransform]

-- | Mirror selection
withMirror :: forall a.
              HttpLib                -- ^ HTTP client
           -> SelectedMirror         -- ^ MVar indicating currently mirror
           -> (LogMessage -> IO ())  -- ^ Logger
           -> [URI]                  -- ^ Out-of-band mirrors
           -> RepoOpts               -- ^ Repository options
           -> Maybe [Mirror]         -- ^ TUF mirrors
           -> IO a                   -- ^ Callback
           -> IO a
withMirror HttpLib{..}
           selectedMirror
           logger
           oobMirrors
           repoOpts
           tufMirrors
           callback
           =
    go orderedMirrors
  where
    go :: [URI] -> IO a
    -- Empty list of mirrors is a bug
    go [] = internalError "No mirrors configured"
    -- If we only have a single mirror left, let exceptions be thrown up
    go [m] = do
      logger $ LogSelectedMirror (show m)
      select m $ callback
    -- Otherwise, catch exceptions and if any were thrown, try with different
    -- mirror
    go (m:ms) = do
      logger $ LogSelectedMirror (show m)
      catchChecked (select m callback) $ \ex -> do
        logger $ LogMirrorFailed (show m) ex
        go ms

    -- TODO: We will want to make the construction of this list configurable.
    orderedMirrors :: [URI]
    orderedMirrors = nub $ concat [
        oobMirrors
      , if repoAllowAdditionalMirrors repoOpts
          then maybe [] (map mirrorUrlBase) tufMirrors
          else []
      ]

    select :: URI -> IO a -> IO a
    select uri =
      bracket_ (modifyMVar_ selectedMirror $ \_ -> return $ Just uri)
               (modifyMVar_ selectedMirror $ \_ -> return Nothing)

{-------------------------------------------------------------------------------
  Download methods
-------------------------------------------------------------------------------}

-- | Download method (downloading or updating)
data DownloadMethod :: * -> * -> * where
    -- Download this file (we never attempt to update this type of file)
    NeverUpdated :: {
        neverUpdatedFormat :: HasFormat fs f
      } -> DownloadMethod fs typ

    -- Download this file (we cannot update this file right now)
    CannotUpdate :: {
        cannotUpdateFormat :: HasFormat fs f
      , cannotUpdateReason :: UpdateFailure
      } -> DownloadMethod fs Binary

    -- Attempt an (incremental) update of this file
    Update :: {
        updateFormat :: HasFormat fs f
      , updateInfo   :: Trusted FileInfo
      , updateLocal  :: Path Absolute
      , updateTail   :: Int54
      } -> DownloadMethod fs Binary
--TODO: ^^ older haddock doesn't support GADT doc comments :-(

pickDownloadMethod :: forall fs typ. RemoteConfig
                   -> AttemptNr
                   -> RemoteFile fs typ
                   -> IO (DownloadMethod fs typ)
pickDownloadMethod RemoteConfig{..} attemptNr remoteFile =
    case remoteFile of
      RemoteTimestamp        -> return $ NeverUpdated (HFZ FUn)
      (RemoteRoot _)         -> return $ NeverUpdated (HFZ FUn)
      (RemoteSnapshot _)     -> return $ NeverUpdated (HFZ FUn)
      (RemoteMirrors _)      -> return $ NeverUpdated (HFZ FUn)
      (RemotePkgTarGz _ _)   -> return $ NeverUpdated (HFZ FGz)
      (RemoteIndex hasGz formats) -> multipleExitPoints $ do
        -- Server must support @Range@ with a byte-range
        rangeSupport <- checkServerCapability cfgCaps serverAcceptRangesBytes
        unless rangeSupport $ exit $ CannotUpdate hasGz UpdateImpossibleUnsupported

        -- We must already have a local file to be updated
        mCachedIndex <- lift $ Cache.getCachedIndex cfgCache (hasFormatGet hasGz)
        cachedIndex  <- case mCachedIndex of
          Nothing -> exit $ CannotUpdate hasGz UpdateImpossibleNoLocalCopy
          Just fp -> return fp

        -- We attempt an incremental update a maximum of 2 times
        -- See 'UpdateFailedTwice' for details.
        when (attemptNr >= 2) $ exit $ CannotUpdate hasGz UpdateFailedTwice

        -- If all these checks pass try to do an incremental update.
        return Update {
             updateFormat = hasGz
           , updateInfo   = formatsLookup hasGz formats
           , updateLocal  = cachedIndex
           , updateTail   = 65536 -- max gzip block size
           }

-- | Download the specified file using the given download method
getFile :: forall fs typ. Throws SomeRemoteError
        => RemoteConfig          -- ^ Internal configuration
        -> AttemptNr             -- ^ Did a security check previously fail?
        -> RemoteFile fs typ     -- ^ File to get
        -> DownloadMethod fs typ -- ^ Selected format
        -> Verify (Some (HasFormat fs), RemoteTemp typ)
getFile cfg@RemoteConfig{..} attemptNr remoteFile method =
    go method
  where
    go :: DownloadMethod fs typ -> Verify (Some (HasFormat fs), RemoteTemp typ)
    go NeverUpdated{..} = do
        cfgLogger $ LogDownloading remoteFile
        download neverUpdatedFormat
    go CannotUpdate{..} = do
        cfgLogger $ LogCannotUpdate remoteFile cannotUpdateReason
        cfgLogger $ LogDownloading remoteFile
        download cannotUpdateFormat
    go Update{..} = do
        cfgLogger $ LogUpdating remoteFile
        update updateFormat updateInfo updateLocal updateTail

    headers :: [HttpRequestHeader]
    headers = httpRequestHeaders cfg attemptNr

    -- Get any file from the server, without using incremental updates
    download :: HasFormat fs f -> Verify (Some (HasFormat fs), RemoteTemp typ)
    download format = do
        (tempPath, h) <- openTempFile (Cache.cacheRoot cfgCache) (uriTemplate uri)
        liftIO $ do
          httpGet headers uri $ \responseHeaders bodyReader -> do
            updateServerCapabilities cfgCaps responseHeaders
            execBodyReader targetPath sz h bodyReader
          hClose h
        cacheIfVerified format $ DownloadedWhole tempPath
      where
        targetPath = TargetPathRepo $ remoteRepoPath' cfgLayout remoteFile format
        uri = formatsLookup format $ remoteFileURI cfgLayout cfgBase remoteFile
        sz  = formatsLookup format $ remoteFileSize remoteFile

    -- Get a file incrementally
    update :: (typ ~ Binary)
           => HasFormat fs f    -- ^ Selected format
           -> Trusted FileInfo  -- ^ Expected info
           -> Path Absolute     -- ^ Location of cached file (after callback)
           -> Int54             -- ^ How much of the tail to overwrite
           -> Verify (Some (HasFormat fs), RemoteTemp typ)
    update format info cachedFile fileTail = do
        currentSz <- liftIO $ getFileSize cachedFile
        let fileSz    = fileLength' info
            range     = (0 `max` (currentSz - fileTail), fileSz)
            range'    = (fromIntegral (fst range), fromIntegral (snd range))
            cacheRoot = Cache.cacheRoot cfgCache
        (tempPath, h) <- openTempFile cacheRoot (uriTemplate uri)
        statusCode <- liftIO $
          httpGetRange headers uri range' $ \statusCode responseHeaders bodyReader -> do
            updateServerCapabilities cfgCaps responseHeaders
            let expectedSize =
                  case statusCode of
                    HttpStatus206PartialContent ->
                      FileSizeExact (snd range - fst range)
                    HttpStatus200OK ->
                      FileSizeExact fileSz
            execBodyReader targetPath expectedSize h bodyReader
            hClose h
            return statusCode
        let downloaded =
              case statusCode of
                HttpStatus206PartialContent ->
                  DownloadedDelta {
                      deltaTemp     = tempPath
                    , deltaExisting = cachedFile
                    , deltaSeek     = fst range
                    }
                HttpStatus200OK ->
                  DownloadedWhole tempPath
        cacheIfVerified format downloaded
      where
        targetPath = TargetPathRepo repoPath
        uri        = modifyUriPath cfgBase (`anchorRepoPathRemotely` repoPath)
        repoPath   = remoteRepoPath' cfgLayout remoteFile format

    cacheIfVerified :: HasFormat fs f -> RemoteTemp typ
                    -> Verify (Some (HasFormat fs), RemoteTemp typ)
    cacheIfVerified format remoteTemp = do
        ifVerified $
          Cache.cacheRemoteFile cfgCache
                                remoteTemp
                                (hasFormatGet format)
                                (mustCache remoteFile)
        return (Some format, remoteTemp)

    httpGetRange :: forall a. Throws SomeRemoteError
                 => [HttpRequestHeader]
                 -> URI
                 -> (Int, Int)
                 -> (HttpStatus -> [HttpResponseHeader] -> BodyReader -> IO a)
                 -> IO a
    HttpLib{..} = cfgHttpLib

{-------------------------------------------------------------------------------
  Execute body reader
-------------------------------------------------------------------------------}

-- | Execute a body reader
--
-- TODO: Deal with minimum download rate.
execBodyReader :: Throws SomeRemoteError
               => TargetPath  -- ^ File source (for error msgs only)
               -> FileSize    -- ^ Maximum file size
               -> Handle      -- ^ Handle to write data too
               -> BodyReader  -- ^ The action to give us blocks from the file
               -> IO ()
execBodyReader file mlen h br = go 0
  where
    go :: Int54 -> IO ()
    go sz = do
      unless (sz `fileSizeWithinBounds` mlen) $
        throwChecked $ SomeRemoteError $ FileTooLarge file mlen
      bs <- br
      if BS.null bs
        then return ()
        else BS.hPut h bs >> go (sz + fromIntegral (BS.length bs))

-- | The file we requested from the server was larger than expected
-- (potential endless data attack)
data FileTooLarge = FileTooLarge {
    fileTooLargePath     :: TargetPath
  , fileTooLargeExpected :: FileSize
  }
  deriving (Typeable)

instance Pretty FileTooLarge where
  pretty FileTooLarge{..} = concat [
      "file returned by server too large: "
    , pretty fileTooLargePath
    , " (expected " ++ expected fileTooLargeExpected ++ " bytes)"
    ]
    where
      expected :: FileSize -> String
      expected (FileSizeExact n) = "exactly " ++ show n
      expected (FileSizeBound n) = "at most " ++ show n

#if MIN_VERSION_base(4,8,0)
deriving instance Show FileTooLarge
instance Exception FileTooLarge where displayException = pretty
#else
instance Exception FileTooLarge
instance Show FileTooLarge where show = pretty
#endif

{-------------------------------------------------------------------------------
  Information about remote files
-------------------------------------------------------------------------------}

remoteFileURI :: RepoLayout -> URI -> RemoteFile fs typ -> Formats fs URI
remoteFileURI repoLayout baseURI = fmap aux . remoteRepoPath repoLayout
  where
    aux :: RepoPath -> URI
    aux repoPath = modifyUriPath baseURI (`anchorRepoPathRemotely` repoPath)

-- | Extracting or estimating file sizes
remoteFileSize :: RemoteFile fs typ -> Formats fs FileSize
remoteFileSize (RemoteTimestamp) =
    FsUn $ FileSizeBound fileSizeBoundTimestamp
remoteFileSize (RemoteRoot mLen) =
    FsUn $ maybe (FileSizeBound fileSizeBoundRoot)
                 (FileSizeExact . fileLength')
                 mLen
remoteFileSize (RemoteSnapshot len) =
    FsUn $ FileSizeExact (fileLength' len)
remoteFileSize (RemoteMirrors len) =
    FsUn $ FileSizeExact (fileLength' len)
remoteFileSize (RemoteIndex _ lens) =
    fmap (FileSizeExact . fileLength') lens
remoteFileSize (RemotePkgTarGz _pkgId len) =
    FsGz $ FileSizeExact (fileLength' len)

-- | Bound on the size of the timestamp
--
-- This is intended as a permissive rather than tight bound.
--
-- The timestamp signed with a single key is 420 bytes; the signature makes up
-- just under 200 bytes of that. So even if the timestamp is signed with 10
-- keys it would still only be 2420 bytes. Doubling this amount, an upper bound
-- of 4kB should definitely be sufficient.
fileSizeBoundTimestamp :: Int54
fileSizeBoundTimestamp = 4096

-- | Bound on the size of the root
--
-- This is intended as a permissive rather than tight bound.
--
-- The variable parts of the root metadata are
--
-- * Signatures, each of which are about 200 bytes
-- * A key environment (mapping from key IDs to public keys), each is of
--   which is also about 200 bytes
-- * Mirrors, root, snapshot, targets, and timestamp role specifications.
--   These contains key IDs, each of which is about 80 bytes.
--
-- A skeleton root metadata is about 580 bytes. Allowing for
--
-- * 100 signatures
-- * 100 mirror keys, 1000 root keys, 100 snapshot keys, 1000 target keys,
--   100 timestamp keys
-- * the corresponding 2300 entries in the key environment
--
-- We end up with a bound of about 665,000 bytes. Doubling this amount, an
-- upper bound of 2MB should definitely be sufficient.
fileSizeBoundRoot :: Int54
fileSizeBoundRoot = 2 * 1024 * 2014

{-------------------------------------------------------------------------------
  Configuration
-------------------------------------------------------------------------------}

-- | Remote repository configuration
--
-- This is purely for internal convenience.
data RemoteConfig = RemoteConfig {
      cfgLayout   :: RepoLayout
    , cfgHttpLib  :: HttpLib
    , cfgBase     :: URI
    , cfgCache    :: Cache
    , cfgCaps     :: ServerCapabilities
    , cfgLogger   :: forall m. MonadIO m => LogMessage -> m ()
    , cfgOpts     :: RepoOpts
    }

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Template for the local file we use to download a URI to
uriTemplate :: URI -> String
uriTemplate = takeFileName . uriPath

fileLength' :: Trusted FileInfo -> Int54
fileLength' = fileLength . fileInfoLength . trusted

{-------------------------------------------------------------------------------
  Files downloaded from the remote repository
-------------------------------------------------------------------------------}

data RemoteTemp :: * -> * where
    DownloadedWhole :: {
        wholeTemp :: Path Absolute
      } -> RemoteTemp a

    -- If we download only the delta, we record both the path to where the
    -- "old" file is stored and the path to the temp file containing the delta.
    -- Then:
    --
    --   When we verify the file, we need both of these paths if we compute
    --   the hash from scratch, or only the path to the delta if we attempt
    --   to compute the hash incrementally (TODO: incremental verification
    --   not currently implemented).
    --
    --   When we copy a file over, we are additionally given a destination
    --   path. In this case, we expect that destination path to be equal to
    --   the path to the old file (and assert this to be the case).
    DownloadedDelta :: {
        deltaTemp     :: Path Absolute
      , deltaExisting :: Path Absolute
      , deltaSeek     :: Int54       -- ^ How much of the existing file to keep
      } -> RemoteTemp Binary
--TODO: ^^ older haddock doesn't support GADT doc comments :-(
--      and add the '*' bullet points back in

instance Pretty (RemoteTemp typ) where
    pretty DownloadedWhole{..} = intercalate " " $ [
        "DownloadedWhole"
      , pretty wholeTemp
      ]
    pretty DownloadedDelta{..} = intercalate " " $ [
        "DownloadedDelta"
      , pretty deltaTemp
      , pretty deltaExisting
      , show deltaSeek
      ]

instance DownloadedFile RemoteTemp where
  downloadedVerify = verifyRemoteFile
  downloadedRead   = readLazyByteString . wholeTemp
  downloadedCopyTo = \f dest ->
    case f of
      DownloadedWhole{..} ->
        renameFile wholeTemp dest
      DownloadedDelta{..} -> do
        unless (deltaExisting == dest) $
          throwIO $ userError "Assertion failure: deltaExisting /= dest"
        -- We need ReadWriteMode in order to be able to seek
        withFile deltaExisting ReadWriteMode $ \h -> do
          hSeek h AbsoluteSeek (fromIntegral deltaSeek)
          BS.L.hPut h =<< readLazyByteString deltaTemp

-- | Verify a file downloaded from the remote repository
--
-- TODO: This currently still computes the hash for the whole file. If we cached
-- the state of the hash generator we could compute the hash incrementally.
-- However, profiling suggests that this would only be a minor improvement.
verifyRemoteFile :: RemoteTemp typ -> Trusted FileInfo -> IO Bool
verifyRemoteFile remoteTemp trustedInfo = do
    sz <- FileLength <$> remoteSize remoteTemp
    if sz /= fileInfoLength (trusted trustedInfo)
      then return False
      else withRemoteBS remoteTemp $
             compareTrustedFileInfo (trusted trustedInfo) . fileInfo
  where
    remoteSize :: RemoteTemp typ -> IO Int54
    remoteSize DownloadedWhole{..} = getFileSize wholeTemp
    remoteSize DownloadedDelta{..} = do
        deltaSize <- getFileSize deltaTemp
        return $ deltaSeek + deltaSize

    -- It is important that we close the file handles when we're done
    -- (esp. since we may not read the whole file)
    withRemoteBS :: RemoteTemp typ -> (BS.L.ByteString -> Bool) -> IO Bool
    withRemoteBS DownloadedWhole{..} callback = do
        withFile wholeTemp ReadMode $ \h -> do
          bs <- BS.L.hGetContents h
          evaluate $ callback bs
    withRemoteBS DownloadedDelta{..} callback =
        withFile deltaExisting ReadMode $ \hExisting ->
          withFile deltaTemp ReadMode $ \hTemp -> do
            existing <- BS.L.hGetContents hExisting
            temp     <- BS.L.hGetContents hTemp
            evaluate $ callback $ BS.L.concat [
                BS.L.take (fromIntegral deltaSeek) existing
              , temp
              ]

