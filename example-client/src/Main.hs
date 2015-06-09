module Main where

import Data.List (isPrefixOf)
import Network.URI
import System.Directory
import System.FilePath

import Distribution.Package

import Hackage.Security.Client
import qualified Hackage.Security.Client.Repository.Local             as Local
import qualified Hackage.Security.Client.Repository.Remote            as Remote
import qualified Hackage.Security.Client.Repository.Remote.HTTP       as Remote.HTTP
import qualified Hackage.Security.Client.Repository.Remote.HttpClient as Remote.HttpClient
import qualified Hackage.Security.Client.Repository.Remote.Curl       as Remote.Curl

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
    localFile = "." </> pkgTarGz pkgId

{-------------------------------------------------------------------------------
  Common functionality
-------------------------------------------------------------------------------}

withRepo :: GlobalOpts -> (Repository -> IO a) -> IO a
withRepo GlobalOpts{..}
    | "http://" `isPrefixOf` globalRepo = withRemoteRepo
    | otherwise                         = withLocalRepo
  where
    withLocalRepo :: (Repository -> IO a) -> IO a
    withLocalRepo = Local.withRepository globalRepo globalCache logTUF

    withRemoteRepo :: (Repository -> IO a) -> IO a
    withRemoteRepo callback =
        withClient $ \httpClient ->
          Remote.withRepository httpClient [baseURI] globalCache logTUF callback
      where
        baseURI :: URI
        baseURI = case parseURI globalRepo of
                    Nothing  -> error $ "Invalid URI: " ++ globalRepo
                    Just uri -> uri

    withClient :: (Remote.HttpClient -> IO a) -> IO a
    withClient =
        case globalHttpClient of
          "HTTP"        -> Remote.HTTP.withClient logHTTP logHTTP
          "http-client" -> Remote.HttpClient.withClient logHTTP
          "curl"        -> Remote.Curl.withClient logHTTP
          _otherwise    -> error "unsupported HTTP client"

    -- used for log messages from the Hackage.Security code
    logTUF :: LogMessage -> IO ()
    logTUF msg = putStrLn $ "# " ++ formatLogMessage msg

    -- used for log messages from the HTTP clients
    logHTTP :: String -> IO ()
    logHTTP = putStrLn
