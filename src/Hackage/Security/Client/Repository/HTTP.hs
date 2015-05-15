module Hackage.Security.Client.Repository.HTTP (
    HttpClient(..)
  , Cache
  , initRepo
  ) where

import Control.Monad
import Network.URI
import System.Directory
import System.FilePath

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local (Cache)
import Hackage.Security.Trusted
import Hackage.Security.TUF
import qualified Hackage.Security.Client.Repository.Local as Local

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implements (such as a conduit based one)
data HttpClient = HttpClient {
    httpClientGet :: forall a. URI -> Maybe Int -> (TempPath -> IO a) -> IO a
  }

initRepo :: HttpClient -> URIAuth -> Cache -> Repository
initRepo http auth cache = Repository {
    repWithRemote    = withRemote http auth cache
  , repGetCached     = Local.getCached     cache
  , repGetCachedRoot = Local.getCachedRoot cache
  , repDeleteCached  = Local.deleteCached  cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: HttpClient
           -> URIAuth
           -> Cache
           -> File (Trusted FileLength)
           -> (TempPath -> IO a)
           -> IO a
withRemote HttpClient{..} auth cache file callback =
    httpClientGet url (fmap trustedFileLength len) $ \tempPath -> do
      result <- callback tempPath
      when (Local.shouldCache file) $ copyFile tempPath localPath
      return result
  where
    (url, len) = fileToURL auth file
    localPath  = cache </> Local.fileToPath file

fileToURL :: URIAuth
          -> File (Trusted FileLength)
          -> (URI, Maybe (Trusted FileLength))
fileToURL auth file =
    case file of
      FileTimestamp -> (mkURI "/static/timestamp.json", Nothing)
  where
    mkURI :: String -> URI
    mkURI p = URI {
        uriScheme = "http:"
      , uriAuthority = Just auth
      , uriPath      = p
      , uriQuery     = ""
      , uriFragment  = ""
      }
