{-# LANGUAGE CPP #-}
module Main where

import Distribution.Package

import Hackage.Security.Client
import Hackage.Security.Util.Path
import qualified Hackage.Security.Client.Repository.Cache             as Cache
import qualified Hackage.Security.Client.Repository.Local             as Local
import qualified Hackage.Security.Client.Repository.Remote            as Remote
import qualified Hackage.Security.Client.Repository.Remote.HTTP       as Remote.HTTP
import qualified Hackage.Security.Client.Repository.Remote.Curl       as Remote.Curl

#if MIN_VERSION_base(4,5,0)
import qualified Hackage.Security.Client.Repository.Remote.HttpClient as Remote.HttpClient
#endif

import ExampleClient.Options

main :: IO ()
main = do
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      Bootstrap threshold -> cmdBootstrap opts threshold
      Check               -> cmdCheck     opts
      Get       pkgId     -> cmdGet       opts pkgId

{-------------------------------------------------------------------------------
  The commands are just thin wrappers around the hackage-security Client API
-------------------------------------------------------------------------------}

cmdBootstrap :: GlobalOpts -> KeyThreshold -> IO ()
cmdBootstrap opts threshold =
    withRepo opts $ \rep -> do
      bootstrap rep (globalRootKeys opts) threshold
      putStrLn "OK"

cmdCheck :: GlobalOpts -> IO ()
cmdCheck opts =
    withRepo opts $ \rep ->
      print =<< checkForUpdates rep (globalCheckExpiry opts)

cmdGet :: GlobalOpts -> PackageIdentifier -> IO ()
cmdGet opts pkgId =
    withRepo opts $ \rep ->
      downloadPackage rep pkgId $ \tempPath ->
        copyFile tempPath localFile
  where
    localFile :: RelativePath
    localFile = castRoot $ repoLayoutPkgFile hackageRepoLayout pkgId

{-------------------------------------------------------------------------------
  Common functionality
-------------------------------------------------------------------------------}

withRepo :: GlobalOpts -> (Repository -> IO a) -> IO a
withRepo GlobalOpts{..} =
    case globalRepo of
      Left  local  -> withLocalRepo  local
      Right remote -> withRemoteRepo remote
  where
    withLocalRepo :: AbsolutePath -> (Repository -> IO a) -> IO a
    withLocalRepo repo =
        Local.withRepository repo
                             cache
                             hackageRepoLayout
                             logTUF

    withRemoteRepo :: URI -> (Repository -> IO a) -> IO a
    withRemoteRepo baseURI callback = withClient $ \httpClient ->
        Remote.withRepository httpClient
                              [baseURI]
                              cache
                              hackageRepoLayout
                              logTUF
                              callback

    withClient :: (Remote.HttpClient -> IO a) -> IO a
    withClient =
        case globalHttpClient of
          "HTTP"        -> Remote.HTTP.withClient logHTTP logHTTP
          "curl"        -> Remote.Curl.withClient logHTTP
#if MIN_VERSION_base(4,5,0)
          "http-client" -> Remote.HttpClient.withClient logHTTP
#endif
          _otherwise    -> error "unsupported HTTP client"

    -- used for log messages from the Hackage.Security code
    logTUF :: LogMessage -> IO ()
    logTUF msg = putStrLn $ "# " ++ formatLogMessage msg

    -- used for log messages from the HTTP clients
    logHTTP :: String -> IO ()
    logHTTP = putStrLn

    cache :: Cache.Cache
    cache = Cache.Cache {
        cacheRoot   = globalCache
      , cacheLayout = cabalCacheLayout
      }
