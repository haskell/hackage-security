module Main where

import Data.List (isPrefixOf)
import Network.URI
import System.Directory
import System.FilePath

import Distribution.Package

import Hackage.Security.Client
import Hackage.Security.Client.Repository
import qualified Hackage.Security.Client.Repository.Local as Local
import qualified Hackage.Security.Client.Repository.HTTP  as Remote

import ExampleClient.Options
import qualified ExampleClient.HttpClient.HTTP    as HttpClient.HTTP
import qualified ExampleClient.HttpClient.Conduit as HttpClient.Conduit

main :: IO ()
main = do
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      Check     -> check opts
      Get pkgId -> get   opts pkgId

{-------------------------------------------------------------------------------
  Checking for updates
-------------------------------------------------------------------------------}

check :: GlobalOpts -> IO ()
check opts =
    withRepo opts $ \rep ->
      print =<< checkForUpdates rep CheckExpiry

{-------------------------------------------------------------------------------
  Downloading packages
-------------------------------------------------------------------------------}

get :: GlobalOpts -> PackageIdentifier -> IO ()
get opts pkgId =
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
    withLocalRepo = Local.withRepository globalRepo globalCache logger

    withRemoteRepo :: (Repository -> IO a) -> IO a
    withRemoteRepo callback =
        withClient putStrLn $ \httpClient ->
          Remote.withRepository httpClient baseURI globalCache logger callback
      where
        baseURI :: URI
        baseURI = case parseURI globalRepo of
                    Nothing  -> error $ "Invalid URI: " ++ globalRepo
                    Just uri -> uri

    withClient :: (String -> IO ()) -> (Remote.HttpClient -> IO a) -> IO a
    withClient =
      case globalHttpClient of
        "HTTP"        -> HttpClient.HTTP.withClient
        "http-client" -> HttpClient.Conduit.withClient
        _otherwise    -> error "unsupported HTTP client"

    logger :: LogMessage -> IO ()
    logger msg = putStrLn $ "# " ++ formatLogMessage msg
