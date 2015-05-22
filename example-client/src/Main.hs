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
check opts = do
    rep <- initRepo opts
    print =<< checkForUpdates rep CheckExpiry

{-------------------------------------------------------------------------------
  Downloading packages
-------------------------------------------------------------------------------}

get :: GlobalOpts -> PackageIdentifier -> IO ()
get opts pkgId = do
    rep <- initRepo opts
    downloadPackage rep pkgId $ \tempPath ->
      copyFile tempPath localFile
  where
    localFile = "." </> pkgTarGz pkgId

{-------------------------------------------------------------------------------
  Common functionality
-------------------------------------------------------------------------------}

initRepo :: GlobalOpts -> IO Repository
initRepo GlobalOpts{..}
    | "http://" `isPrefixOf` globalRepo = initRemoteRepo
    | otherwise                         = initLocalRepo
  where
    initLocalRepo :: IO Repository
    initLocalRepo = return $ Local.initRepo globalRepo globalCache logger

    initRemoteRepo :: IO Repository
    initRemoteRepo = do
        httpClient <- initClient putStrLn
        return $ Remote.initRepo httpClient baseURI globalCache logger
      where
        baseURI :: URI
        baseURI = case parseURI globalRepo of
                    Nothing  -> error $ "Invalid URI: " ++ globalRepo
                    Just uri -> uri

    initClient :: (String -> IO ()) -> IO Remote.HttpClient
    initClient =
      case globalHttpClient of
        "HTTP"         -> HttpClient.HTTP.initClient
        "http-conduit" -> HttpClient.Conduit.initClient
        _otherwise     -> error "unsupported HTTP client"

    logger :: LogMessage -> IO ()
    logger msg = putStrLn $ "# " ++ formatLogMessage msg
