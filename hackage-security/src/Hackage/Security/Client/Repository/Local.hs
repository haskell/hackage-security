-- | Local repository
module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , withRepository
  ) where

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Cache
import Hackage.Security.Client.Formats
import Hackage.Security.TUF
import Hackage.Security.Util.Path

-- | Location of the repository
--
-- Note that we regard the local repository as immutable; we cache files just
-- like we do for remote repositories.
type LocalRepo = Path (Rooted Absolute)

-- | Initialize the repository (and cleanup resources afterwards)
--
-- Like a remote repository, a local repository takes a RepoLayout as argument;
-- but where the remote repository interprets this RepoLayout relative to a URL,
-- the local repository interprets it relative to a local directory.
--
-- It uses the same cache as the remote repository.
withRepository
  :: LocalRepo             -- ^ Location of local repository
  -> Cache                 -- ^ Location of local cache
  -> RepoLayout            -- ^ Repository layout
  -> (LogMessage -> IO ()) -- ^ Logger
  -> (Repository -> IO a)  -- ^ Callback
  -> IO a
withRepository repo cache repLayout logger callback = callback Repository {
      repWithRemote    = withRemote repLayout repo cache
    , repGetCached     = getCached     cache
    , repGetCachedRoot = getCachedRoot cache
    , repClearCache    = clearCache    cache
    , repGetFromIndex  = getFromIndex  cache (repoIndexLayout repLayout)
    , repWithMirror    = mirrorsUnsupported
    , repLog           = logger
    , repLayout        = repLayout
    , repDescription   = "Local repository at " ++ show repo
    }

-- | Get a file from the server
withRemote :: RepoLayout -> LocalRepo -> Cache
           -> RemoteFile fs -> (SelectedFormat fs -> TempPath -> IO a) -> IO a
withRemote repoLayout repo cache remoteFile callback = do
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
                              (remoteFilePath repoLayout remoteFile)
    remotePath = anchorRepoPathLocally repo remotePath'
