module TestSuite.InMemCache (
    InMemCache(..)
  , newInMemCache
  ) where

-- base
import Control.Exception
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy   as BS.L

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.JSON
import Hackage.Security.Util.Path

-- TestSuite
import TestSuite.Util.StrictMVar
import TestSuite.InMemRepo

data InMemCache = InMemCache {
      inMemCacheGet     :: CachedFile -> IO (Maybe AbsolutePath)
    , inMemCacheGetRoot :: IO AbsolutePath
    , inMemCacheClear   :: IO ()
    , inMemCachePut     :: forall f typ. InMemFile typ -> Format f -> IsCached typ -> IO ()
    }

newInMemCache :: AbsolutePath -> RepoLayout -> IO InMemCache
newInMemCache tempDir layout = do
    state <- newMVar $ initLocalState layout
    return InMemCache {
        inMemCacheGet     = get     state tempDir
      , inMemCacheGetRoot = getRoot state tempDir
      , inMemCacheClear   = clear   state
      , inMemCachePut     = put     state
      }

{-------------------------------------------------------------------------------
  "Local" state (the files we "cached")
-------------------------------------------------------------------------------}

data LocalState = LocalState {
      cacheRepoLayout :: !RepoLayout
    , cachedRoot      :: !(Maybe (Signed Root))
    , cachedMirrors   :: !(Maybe (Signed Mirrors))
    , cachedTimestamp :: !(Maybe (Signed Timestamp))
    , cachedSnapshot  :: !(Maybe (Signed Snapshot))

    -- We cache only the uncompressed index

    -- (we can unambiguously construct the @.tar@ from the @.tar.gz@,
    -- but not the other way around)
    , cachedIndex :: Maybe BS.L.ByteString
    }

cachedRoot' :: LocalState -> Signed Root
cachedRoot' LocalState{..} = needRoot cachedRoot

needRoot :: Maybe a -> a
needRoot Nothing    = error "InMemCache: no root info (did you bootstrap?)"
needRoot (Just root) = root

initLocalState :: RepoLayout -> LocalState
initLocalState layout = LocalState {
      cacheRepoLayout = layout
    , cachedRoot      = Nothing
    , cachedMirrors   = Nothing
    , cachedTimestamp = Nothing
    , cachedSnapshot  = Nothing
    , cachedIndex     = Nothing
    }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- | Get a cached file (if available)
get :: MVar LocalState -> AbsolutePath -> CachedFile -> IO (Maybe AbsolutePath)
get state cacheTempDir cachedFile =
      case cachedFile of
        CachedRoot      -> serve "root.json"      $ render cachedRoot
        CachedMirrors   -> serve "mirrors.json"   $ render cachedMirrors
        CachedTimestamp -> serve "timestamp.json" $ render cachedTimestamp
        CachedSnapshot  -> serve "snapshot.json"  $ render cachedSnapshot
  where
    render :: forall b. ToJSON WriteJSON b
           => (LocalState -> Maybe b)
           -> (LocalState -> Maybe BS.L.ByteString)
    render f st = renderJSON (cacheRepoLayout st) `fmap` (f st)

    serve :: String
          -> (LocalState -> Maybe BS.L.ByteString)
          -> IO (Maybe AbsolutePath)
    serve template f =
      withMVar state $ \st ->
        case f st of
          Nothing -> return Nothing
          Just bs -> do (tempFile, h) <- openTempFile' cacheTempDir template
                        BS.L.hPut h bs
                        hClose h
                        return $ Just tempFile

-- | Get the cached root
getRoot :: MVar LocalState -> AbsolutePath -> IO AbsolutePath
getRoot state cacheTempDir =
    needRoot `fmap` get state cacheTempDir CachedRoot

-- | Clear all cached data
clear :: MVar LocalState -> IO ()
clear state = modifyMVar_ state $ \st -> return st {
      cachedMirrors   = Nothing
    , cachedTimestamp = Nothing
    , cachedSnapshot  = Nothing
    , cachedIndex     = Nothing
    }

-- | Cache a previously downloaded remote file
put :: MVar LocalState -> InMemFile typ -> Format f -> IsCached typ -> IO ()
put state = put' state . inMemFileRender

put' :: MVar LocalState -> BS.L.ByteString -> Format f -> IsCached typ -> IO ()
put' state bs = go
  where
    go :: Format f -> IsCached typ -> IO ()
    go _   DontCache   = return ()
    go FUn (CacheAs f) = go' f
    go FGz (CacheAs _) = error "put: the impossible happened"
    go FUn CacheIndex  = modifyMVar_ state $ \st -> return st {
                             cachedIndex = Just bs
                           }
    go FGz CacheIndex  = modifyMVar_ state $ \st -> return st {
                             cachedIndex = Just (GZip.decompress bs)
                           }

    go' :: CachedFile -> IO ()
    go' CachedRoot      = go'' $ \x st -> st { cachedRoot      = Just x }
    go' CachedTimestamp = go'' $ \x st -> st { cachedTimestamp = Just x }
    go' CachedSnapshot  = go'' $ \x st -> st { cachedSnapshot  = Just x }
    go' CachedMirrors   = go'' $ \x st -> st { cachedMirrors   = Just x }

    go'' :: forall a. FromJSON ReadJSON_Keys_Layout a
         => (a -> LocalState -> LocalState) -> IO ()
    go'' f = do
      modifyMVar_ state $ \st@LocalState{..} -> do
        let keyEnv = rootKeys . signed . cachedRoot' $ st
        case parseJSON_Keys_Layout keyEnv cacheRepoLayout bs of
           Left  err    -> throwIO err
           Right parsed -> return $ f parsed st
