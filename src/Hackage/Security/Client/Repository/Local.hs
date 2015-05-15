module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , Cache
  , initRepo
    -- * Low-level API (for the benefit of other Repository implementations)
  , getCached
  , getCachedRoot
  , deleteCached
  , fileToPath
  , shouldCache
  ) where

import Control.Exception
import Control.Monad
import System.Directory
import System.FilePath

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client.Repository
import Hackage.Security.Trusted
import Hackage.Security.TUF

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
  , repDeleteCached  = deleteCached  cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: LocalRepo
           -> Cache
           -> File (Trusted FileLength)
           -> (TempPath -> IO a)
           -> IO a
withRemote repo cache file callback = do
    result <- callback remotePath
    when (shouldCache file) $ copyFile remotePath localPath
    return result
  where
    remotePath = repo  </> fileToPath file
    localPath  = cache </> fileToPath file

-- | Get a cached file (if available)
getCached :: Cache -> File () -> IO (Maybe FilePath)
getCached cache file = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cache </> fileToPath file

-- | Get the cached root
getCachedRoot :: Cache -> IO FilePath
getCachedRoot cache = do
    mPath <- getCached cache $ FileRoot Nothing
    case mPath of
      Just path -> return path
      Nothing   -> throwIO $ userError "Client missing root info"

-- | Delete a previously downloaded remote file
deleteCached :: Cache -> File () -> IO ()
deleteCached cache file = removeFile localPath
  where
    localPath = cache </> fileToPath file

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

fileToPath :: File a -> FilePath
fileToPath FileTimestamp          = "timestamp.json"
fileToPath (FileRoot _)           = "root.json"
fileToPath (FileSnapshot _)       = "snapshot.json"
fileToPath (FileIndex {})         = "00-index.tar.gz"
fileToPath (FilePkgTarGz pkgId _) = pkgLoc pkgId </> pkgTarGz pkgId
fileToPath (FilePkgMeta  pkgId)   = pkgLoc pkgId </> "targets.json"

shouldCache :: File a -> Bool
shouldCache FileTimestamp      = True
shouldCache (FileRoot _)       = True
shouldCache (FileSnapshot _)   = True
shouldCache (FileIndex {})     = True
shouldCache (FilePkgTarGz _ _) = False
shouldCache (FilePkgMeta  _)   = False

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
