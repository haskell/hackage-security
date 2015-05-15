module Hackage.Security.Client.Repository.HTTP (
    HttpClient(..)
  , FileSize(..)
  , Cache
  , initRepo
  ) where

import Network.URI
import System.Directory
import System.FilePath

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local (Cache)
import qualified Hackage.Security.Client.Repository.Local as Local

{-------------------------------------------------------------------------------
  Top-level API
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
  | FileSizeUnknown

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implements (such as a conduit based one)
data HttpClient = HttpClient {
    httpClientGet :: forall a. URI -> FileSize -> (TempPath -> IO a) -> IO a
  }

initRepo :: HttpClient -> URIAuth -> Cache -> Repository
initRepo http auth cache = Repository {
    repWithRemote    = withRemote http auth cache
  , repGetCached     = Local.getCached     cache
  , repGetCachedRoot = Local.getCachedRoot cache
  , repClearCache    = Local.clearCache    cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: HttpClient -> URIAuth -> Cache
           -> RemoteFile -> (TempPath -> IO a) -> IO a
withRemote HttpClient{..} auth cache remoteFile callback =
    httpClientGet url sz $ \tempPath -> do
      result <- callback tempPath
      case mustCache remoteFile of
        Nothing ->
          return ()
        Just cachedFile -> do
          let localPath = cache </> Local.cachedFilePath cachedFile
          copyFile tempPath localPath
      return result
  where
    (url, sz) = remoteFileURL auth remoteFile

-- TODO: Provide upper bounds
remoteFileURL :: URIAuth -> RemoteFile -> (URI, FileSize)
remoteFileURL auth file =
    case file of
      RemoteTimestamp ->
        (mkURI "/static/timestamp.json", FileSizeUnknown)
  where
    mkURI :: String -> URI
    mkURI p = URI {
        uriScheme = "http:"
      , uriAuthority = Just auth
      , uriPath      = p
      , uriQuery     = ""
      , uriFragment  = ""
      }
