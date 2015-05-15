module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , Cache
  , initRepo
    -- * Low-level API (for the benefit of other Repository implementations)
  , getCached
  , getCachedRoot
  , clearCache
  , cachedFilePath
  ) where

import Control.Exception
import System.Directory
import System.FilePath

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client.Repository

{-------------------------------------------------------------------------------
  Top-level
-------------------------------------------------------------------------------}

type LocalRepo = FilePath
type Cache     = FilePath

-- | Initialy a local repository
initRepo :: LocalRepo -> Cache -> Repository
initRepo repo cache = Repository {
    repWithRemote    = withRemote repo cache
  , repGetCached     = getCached     cache
  , repGetCachedRoot = getCachedRoot cache
  , repClearCache    = clearCache    cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: LocalRepo -> Cache
           -> RemoteFile -> (TempPath -> IO a) -> IO a
withRemote repo cache remoteFile callback = do
    result <- callback remotePath
    case mustCache remoteFile of
      Nothing ->
        return ()
      Just cachedFile -> do
        let localPath = cache </> cachedFilePath cachedFile
        -- TODO: (here and elsewhere): use atomic file operation instead
        copyFile remotePath localPath
    return result
  where
    remotePath = repo </> remoteFilePath remoteFile

-- | Get a cached file (if available)
getCached :: Cache -> CachedFile -> IO (Maybe FilePath)
getCached cache cachedFile = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cache </> cachedFilePath cachedFile

-- | Get the cached root
getCachedRoot :: Cache -> IO FilePath
getCachedRoot cache = do
    mPath <- getCached cache CachedRoot
    case mPath of
      Just path -> return path
      Nothing   -> throwIO $ userError "Client missing root info"

-- | Delete a previously downloaded remote file
clearCache :: Cache -> IO ()
clearCache cache = do
    removeFile $ cache </> cachedFilePath CachedTimestamp
    removeFile $ cache </> cachedFilePath CachedSnapshot

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

remoteFilePath :: RemoteFile -> FilePath
remoteFilePath RemoteTimestamp          = "timestamp.json"
remoteFilePath (RemoteRoot _)           = "root.json"
remoteFilePath (RemoteSnapshot _)       = "snapshot.json"
remoteFilePath (RemoteIndex {})         = "00-index.tar.gz"
remoteFilePath (RemotePkgTarGz pkgId _) = pkgLoc pkgId </> pkgTarGz pkgId

cachedFilePath :: CachedFile -> FilePath
cachedFilePath CachedTimestamp = "timestamp.json"
cachedFilePath CachedRoot      = "root.json"
cachedFilePath CachedSnapshot  = "snapshot.json"
cachedFilePath CachedIndexTar  = "00-index.tar"

pkgLoc :: PackageIdentifier -> FilePath
pkgLoc pkgId = display (packageName pkgId) </> display (packageVersion pkgId)

-- TODO: Are we hardcoding information here that's available from Cabal somewhere?
pkgTarGz :: PackageIdentifier -> FilePath
pkgTarGz pkgId = concat [
      display (packageName pkgId)
    , "-"
    , display (packageVersion pkgId)
    , ".tar.gz"
    ]
