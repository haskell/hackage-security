module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , Cache
  , withRepository
  ) where

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local.Internal
import Hackage.Security.Client.Formats
import Hackage.Security.Util.Path

-- | Location of the repository
--
-- Note that we regard the local repository as immutable; we cache files just
-- like we do for remote repositories.
type LocalRepo = Path (Rooted Absolute)

-- | Initialize the repository (and cleanup resources afterwards)
withRepository
  :: LocalRepo             -- ^ Location of local repository
  -> Cache                 -- ^ Location of local cache
  -> (LogMessage -> IO ()) -- ^ Logger
  -> (Repository -> IO a)  -- ^ Callback
  -> IO a
withRepository repo cache logger callback = callback Repository {
    repWithRemote    = withRemote repo cache
  , repGetCached     = getCached     cache
  , repGetCachedRoot = getCachedRoot cache
  , repClearCache    = clearCache    cache
  , repGetFromIndex  = getFromIndex  cache
  , repWithMirror    = mirrorsUnsupported
  , repLog           = logger
  , repDescription   = "Local repository at " ++ show repo
  }

-- | Get a file from the server
withRemote :: LocalRepo -> Cache
           -> RemoteFile fs -> (SelectedFormat fs -> TempPath -> IO a) -> IO a
withRemote repo cache remoteFile callback = do
    result <- callback format remotePath
    cacheRemoteFile cache
                    remotePath
                    (selectedFormatSome format)
                    (mustCache remoteFile)
    return result
  where
    (format, remotePath') = formatsPrefer
                              (remoteFileNonEmpty remoteFile)
                              FUn
                              (remoteFilePath remoteFile)
    remotePath = repo </> remotePath'
