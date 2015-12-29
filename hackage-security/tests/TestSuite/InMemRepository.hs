module TestSuite.InMemRepository (
    newInMemRepository
  ) where

-- stdlib
import Control.Concurrent

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Verify
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Some

-- TestSuite
import TestSuite.InMemCache
import TestSuite.InMemRepo

newInMemRepository :: RepoLayout
                   -> IndexLayout
                   -> InMemRepo
                   -> InMemCache
                   -> (LogMessage -> IO ())
                   -> IO (Repository InMemFile)
newInMemRepository layout indexLayout repo cache logger = do
    cacheLock <- newMVar ()
    return $ Repository {
        repGetRemote     = getRemote     repo cache
      , repGetCached     = inMemCacheGet      cache
      , repGetCachedRoot = inMemCacheGetRoot  cache
      , repClearCache    = inMemCacheClear    cache
      , repLockCache     = withMVar cacheLock . const
      , repWithIndex     = error "newInMemRepository: repWithIndex TODO"
      , repGetIndexIdx   = error "newInMemRepository: repGetIndexIdx TODO"
      , repWithMirror    = withMirror
      , repLog           = logger
      , repLayout        = layout
      , repIndexLayout   = indexLayout
      , repDescription   = "In memory repository"
      }

{-------------------------------------------------------------------------------
  Repository methods
-------------------------------------------------------------------------------}

-- | Get a file from the server
getRemote :: forall fs typ. Throws SomeRemoteError
          => InMemRepo
          -> InMemCache
          -> AttemptNr
          -> RemoteFile fs typ
          -> Verify (Some (HasFormat fs), InMemFile typ)
getRemote InMemRepo{..} InMemCache{..} _isRetry remoteFile = do
    (Some format, inMemFile) <- inMemRepoGet remoteFile
    ifVerified $ inMemCachePut inMemFile (hasFormatGet format) (mustCache remoteFile)
    return (Some format, inMemFile)

-- | Mirror selection
withMirror :: forall a. Maybe [Mirror] -> IO a -> IO a
withMirror Nothing   callback = callback
withMirror (Just []) callback = callback
withMirror _ _ = error "Mirror selection not implemented"
