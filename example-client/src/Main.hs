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
    let rep = initRepo opts
    print =<< checkForUpdates rep CheckExpiry

{-------------------------------------------------------------------------------
  Downloading packages
-------------------------------------------------------------------------------}

get :: GlobalOpts -> PackageIdentifier -> IO ()
get opts pkgId = do
    let rep = initRepo opts
    downloadPackage rep pkgId $ \tempPath ->
      copyFile tempPath localFile
  where
    localFile = "." </> pkgTarGz pkgId

{-------------------------------------------------------------------------------
  Common functionality
-------------------------------------------------------------------------------}

initRepo :: GlobalOpts -> Repository
initRepo GlobalOpts{..}
    | "http://" `isPrefixOf` globalRepo = initRemoteRepo
    | otherwise                         = initLocalRepo
  where
    initLocalRepo :: Repository
    initLocalRepo = Local.initRepo globalRepo globalCache

    initRemoteRepo :: Repository
    initRemoteRepo = Remote.initRepo httpClient baseURI globalCache
      where
        baseURI :: URI
        baseURI = case parseURI globalRepo of
                    Nothing  -> error $ "Invalid URI: " ++ globalRepo
                    Just uri -> uri

    httpClient :: Remote.HttpClient
    httpClient =
      case globalHttpClient of
        "HTTP"         -> HttpClient.HTTP.initClient
        "http-conduit" -> HttpClient.Conduit.initClient
        _otherwise     -> error "unsupported HTTP client"
