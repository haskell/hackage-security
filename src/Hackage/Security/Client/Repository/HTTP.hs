module Hackage.Security.Client.Repository.HTTP (
    -- * Server capabilities
    ServerCapabilities -- opaque
  , newServerCapabilities
  , getServerSupportsAcceptBytes
  , setServerSupportsAcceptBytes
    -- * Abstracting over HTTP libraries
  , BodyReader
  , HttpClient(..)
  , FileSize(..)
  , Cache
    -- * Top-level API
  , initRepo
  ) where

import Control.Concurrent
import Control.Monad.Except
import Network.URI
import System.FilePath
import System.IO
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local (Cache)
import Hackage.Security.Trusted
import Hackage.Security.TUF
import Hackage.Security.Util.IO
import Hackage.Security.Util.Some
import qualified Hackage.Security.Client.Repository.Local as Local

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
--
-- This is not exported; we only export functions that work on
-- 'ServerCapabilities'.
data ServerCapabilities_ = ServerCapabilities {
      serverSupportsAcceptBytes :: Bool
    }

newServerCapabilities :: IO ServerCapabilities
newServerCapabilities = SC <$> newMVar ServerCapabilities {
      serverSupportsAcceptBytes = False
    }

setServerSupportsAcceptBytes :: ServerCapabilities -> Bool -> IO ()
setServerSupportsAcceptBytes (SC mv) x = modifyMVar_ mv $ \caps ->
    return $ caps { serverSupportsAcceptBytes = x }

getServerSupportsAcceptBytes :: ServerCapabilities -> IO Bool
getServerSupportsAcceptBytes (SC mv) = withMVar mv $ \caps ->
    return $ serverSupportsAcceptBytes caps

{-------------------------------------------------------------------------------
  Abstraction over HTTP clients (such as HTTP, http-conduit, etc.)
-------------------------------------------------------------------------------}

data FileSize =
    -- | For most files we download we know the exact size beforehand
    -- (because this information comes from the snapshot or delegated info)
    FileSizeExact Int

    -- | For some files we might not know the size beforehand, but we might
    -- be able to provide an upper bound (timestamp, root info)
  | FileSizeBound Int

    -- | If we don't want to guess, we can also just indicate we have no idea
    -- what size file we are expecting. This means we cannot protect against
    -- endless data attacks however.
    --
    -- TODO: Once we put in estimates we should get rid of this.
  | FileSizeUnknown

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implementations (such as a conduit based one)
data HttpClient = HttpClient {
    -- | Download a file
    httpClientGet :: forall a. URI -> (BodyReader -> IO a) -> IO a

    -- | Download a byte range
    --
    -- Range is starting and (exclusive) end offset in bytes.
  , httpClientGetRange :: forall a. URI -> (Int, Int) -> (BodyReader -> IO a) -> IO a

    -- | Server capabilities
    --
    -- HTTP clients should use 'newServerCapabilities' on initialization.
  , httpClientCapabilities :: ServerCapabilities
  }

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initRepo :: HttpClient            -- ^ Implementation of the HTTP protocol
         -> URI                   -- ^ Base URI
         -> Cache                 -- ^ Location of local cache
         -> (LogMessage -> IO ()) -- ^ Logger
         -> Repository
initRepo http auth cache logger = Repository {
    repWithRemote    = withRemote http auth cache logger
  , repGetCached     = Local.getCached     cache
  , repGetCachedRoot = Local.getCachedRoot cache
  , repClearCache    = Local.clearCache    cache
  , repGetFromIndex  = Local.getFromIndex  cache
  , repLog           = logger
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
--
-- TODO: We need to deal with the combined timestamp/snapshot thing
withRemote :: HttpClient -> URI -> Cache
           -> (LogMessage -> IO ())
           -> RemoteFile fs
           -> (SelectedFormat fs -> TempPath -> IO a) -> IO a
withRemote httpClient baseURI cache logger remoteFile callback = do
    mIncremental <- shouldDoIncremental httpClient cache remoteFile
    case mIncremental of
      Left reason -> do
        logger $ LogDownloading (Some remoteFile) reason
        getFile httpClient baseURI cache callback remoteFile
      Right (sf, len, fp) -> do
        logger $ LogUpdating (Some remoteFile)
        -- TODO: Catch checksum exceptions, and retry without using incremental
        -- updates (verify that we don't first re-try with root info)
        -- Test by bootstrapping the repo, in which case the incremental update
        -- will fail (provided the index is bigger?)
        incTar httpClient baseURI cache (callback sf) len fp

-- | Should we do an incremental update?
--
-- Returns either 'Left' the reason why we cannot do an incremental update,
-- or else 'Right' the name of the local file that we should update.
shouldDoIncremental
  :: forall fs. HttpClient -> Cache -> RemoteFile fs
  -> IO (Either String (SelectedFormat fs, Trusted FileLength, FilePath))
shouldDoIncremental HttpClient{..} cache remoteFile = runExceptT $ do
    -- Currently the only file which we download incrementally is the index
    formats :: Formats fs (Trusted FileLength) <-
      case remoteFile of
        RemoteIndex _ lens -> return lens
        _ -> throwError "We can only download the index incrementally"

    -- The server must be able to provide the index in uncompressed form
    -- NOTE: The two @SZ Fun@ expressions here have different types.
    (selected :: SelectedFormat fs, len :: Trusted FileLength) <-
      case formats of
        FsUn   lenUn   -> return (SZ FUn, lenUn)
        FsUnGz lenUn _ -> return (SZ FUn, lenUn)
        _ -> throwError "Server does not provide uncompressed index"

    -- Server must support @Range@ with a byte-range
    supportsAcceptBytes <- lift $ getServerSupportsAcceptBytes httpClientCapabilities
    unless supportsAcceptBytes $
      throwError "Server does not support Range header"

    -- We already have a local file to be updated
    -- (if not we should try to download the initial file in compressed form)
    cachedIndex <- do
      mCachedIndex <- lift $ Local.getCachedIndex cache
      case mCachedIndex of
        Nothing -> throwError "No previously downloaded index"
        Just fp -> return fp

    -- TODO: Other factors to decide whether or not we want to do incremental updates
    -- TODO: (Not here:) deal with transparent compression of the update
    -- (but see <https://github.com/haskell/cabal/issues/678> and
    -- @Distribution.Client.GZipUtils@ in @cabal-install@)

    return (selected, len, cachedIndex)

-- | Get any file from the server, without using incremental updates
getFile :: HttpClient -> URI -> Cache
        -> (SelectedFormat fs -> TempPath -> IO a)
        -> RemoteFile fs -> IO a
getFile HttpClient{..} baseURI cache callback remoteFile =
    withSystemTempFile (takeFileName (uriPath uri)) $ \tempPath h -> do
      -- We are careful NOT to scope the remainder of the computation underneath
      -- the httpClientGet
      httpClientGet uri $ execBodyReader sz h
      hClose h
      result <- callback format tempPath
      Local.cacheRemoteFile cache
                            tempPath
                            (selectedFormatSome format)
                            (mustCache remoteFile)
      return result
  where
    (format, (uri, sz)) = formatsPrefer
                            (remoteFileNonEmpty remoteFile)
                            FGz
                            (formatsZip
                              (remoteFileURI baseURI remoteFile)
                              (remoteFileSize remoteFile))

-- | Get a tar file incrementally
--
-- Sadly, this has some tar-specific functionality
incTar :: HttpClient -> URI -> Cache
       -> (TempPath -> IO a)
       -> Trusted FileLength -> FilePath -> IO a
incTar HttpClient{..} baseURI cache callback len cachedFile = do
    -- TODO: Once we have a local tarball index, this is not necessary
    currentSize <- getFileSize cachedFile
    let currentMinusTrailer = currentSize - 1024
        range   = (fromInteger currentMinusTrailer, trustedFileLength len)
        rangeSz = FileSizeExact (snd range - fst range)
    withSystemTempFile (takeFileName (uriPath uri)) $ \tempPath h -> do
      BS.L.hPut h =<< BS.L.readFile cachedFile
      hSeek h AbsoluteSeek currentMinusTrailer
      -- As in 'getFile', make sure we don't scope the remainder of the
      -- computation underneath the httpClientGetRange
      httpClientGetRange uri range $ execBodyReader rangeSz h
      hClose h
      result <- callback tempPath
      Local.cacheRemoteFile cache tempPath (Some FUn) CacheIndex
      return result
  where
    -- TODO: There are hardcoded references to "00-index.tar" and
    -- "00-index.tar.gz" everwhere. We should probably abstract over that.
    uri = baseURI { uriPath = uriPath baseURI </> "00-index.tar" }

{-------------------------------------------------------------------------------
  Body readers
-------------------------------------------------------------------------------}

-- | An @IO@ action that represents an incoming response body coming from the
-- server.
--
-- The action gets a single chunk of data from the response body, or an empty
-- bytestring if no more data is available.
--
-- This definition is copied from the @http-client@ package.
type BodyReader = IO BS.ByteString

-- | Execute a body reader
--
-- NOTE: This intentially does NOT use the @with..@ pattern: we want to execute
-- the entire body reader (or cancel it) and write the results to a file and
-- then continue. We do NOT want to scope the remainder of the computation
-- as part of the same HTTP request.
--
-- TODO: Deal with maximum file sizes and minimum download rate.
execBodyReader :: FileSize -> Handle -> BodyReader -> IO ()
execBodyReader mlen h br = go
  where
    go = do bs <- br
            if BS.null bs
              then return ()
              else BS.hPut h bs >> go

{-------------------------------------------------------------------------------
  Information about remote files
-------------------------------------------------------------------------------}

remoteFileURI :: URI -> RemoteFile fs -> Formats fs URI
remoteFileURI baseURI = fmap aux . remoteFilePath
  where
    aux :: FilePath -> URI
    aux remotePath = baseURI { uriPath = uriPath baseURI </> remotePath }

-- | Extracting or estimating file sizes
--
-- TODO: Put in estimates
remoteFileSize :: RemoteFile fs -> Formats fs FileSize
remoteFileSize (RemoteTimestamp) =
    FsUn FileSizeUnknown
remoteFileSize (RemoteRoot mLen) =
    FsUn $ maybe FileSizeUnknown (FileSizeExact . trustedFileLength) mLen
remoteFileSize (RemoteSnapshot len) =
    FsUn $ FileSizeExact (trustedFileLength len)
remoteFileSize (RemoteIndex _ lens) =
    fmap (FileSizeExact . trustedFileLength) lens
remoteFileSize (RemotePkgTarGz _pkgId len) =
    FsGz $ FileSizeExact (trustedFileLength len)
