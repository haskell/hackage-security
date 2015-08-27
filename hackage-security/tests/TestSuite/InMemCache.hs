module TestSuite.InMemCache (
    InMemCache(..)
  , newInMemCache
  ) where

-- base
import Control.Concurrent
import Control.Exception
import Data.Maybe (fromJust)
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy   as BS.L

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.JSON
import Hackage.Security.Util.Path

data InMemCache = InMemCache {
      inMemGetCached     :: CachedFile -> IO (Maybe AbsolutePath)
    , inMemGetCachedRoot :: IO AbsolutePath
    , inMemClearCache    :: IO ()
    , inMemCacheFile     :: forall f. TempPath -> Format f -> IsCached -> IO ()
    }

newInMemCache :: AbsolutePath -> RepoLayout -> Signed Root -> IO InMemCache
newInMemCache tempDir layout root = do
    state <- newMVar $ initLocalState layout root
    return InMemCache {
        inMemGetCached     = getCached     state tempDir
      , inMemGetCachedRoot = getCachedRoot state tempDir
      , inMemClearCache    = clearCache    state
      , inMemCacheFile     = cacheFile     state
      }

{-------------------------------------------------------------------------------
  "Local" state (the files we "cached")
-------------------------------------------------------------------------------}

data LocalState = LocalState {
      cacheRepoLayout :: RepoLayout
    , cachedRoot      :: Signed Root
    , cachedMirrors   :: Maybe (Signed Mirrors)
    , cachedTimestamp :: Maybe (Signed Timestamp)
    , cachedSnapshot  :: Maybe (Signed Snapshot)

    -- We cache only the uncompressed index

    -- (we can unambiguously construct the @.tar@ from the @.tar.gz@,
    -- but not the other way around)
    , cachedIndex :: Maybe BS.L.ByteString
    }

initLocalState :: RepoLayout -> Signed Root -> LocalState
initLocalState layout root = LocalState {
      cacheRepoLayout = layout
    , cachedRoot      = root
    , cachedMirrors   = Nothing
    , cachedTimestamp = Nothing
    , cachedSnapshot  = Nothing
    , cachedIndex     = Nothing
    }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- | Get a cached file (if available)
getCached :: MVar LocalState -> AbsolutePath -> CachedFile -> IO (Maybe AbsolutePath)
getCached state cacheTempDir cachedFile =
      case cachedFile of
        CachedRoot      -> serve "root.json"      $ render (Just `fmap` cachedRoot)
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
          Just bs -> do (tempFile, h) <- openTempFile cacheTempDir template
                        BS.L.hPut h bs
                        hClose h
                        return $ Just tempFile

-- | Get the cached root
getCachedRoot :: MVar LocalState -> AbsolutePath -> IO AbsolutePath
getCachedRoot state cacheTempDir =
    fromJust `fmap` getCached state cacheTempDir CachedRoot

-- | Clear all cached data
clearCache :: MVar LocalState -> IO ()
clearCache state = modifyMVar_ state $ \st -> return st {
      cachedMirrors   = Nothing
    , cachedTimestamp = Nothing
    , cachedSnapshot  = Nothing
    , cachedIndex     = Nothing
    }

-- | Cache a previously downloaded remote file
cacheFile :: MVar LocalState -> TempPath -> Format f -> IsCached -> IO ()
cacheFile state tempPath format isCached = do
    bs <- readLazyByteString tempPath
    cacheFile' state bs format isCached

cacheFile' :: MVar LocalState -> BS.L.ByteString -> Format f -> IsCached -> IO ()
cacheFile' state bs = go
  where
    go :: Format f -> IsCached -> IO ()
    go _   DontCache   = return ()
    go FUn (CacheAs f) = go' f
    go FGz (CacheAs _) = error "cacheFile: the impossible happened"
    go FUn CacheIndex  = modifyMVar_ state $ \st -> return st {
                             cachedIndex = Just bs
                           }
    go FGz CacheIndex  = modifyMVar_ state $ \st -> return st {
                             cachedIndex = Just (GZip.decompress bs)
                           }

    go' :: CachedFile -> IO ()
    go' CachedRoot      = go'' $ \x st -> st { cachedRoot      = x }
    go' CachedTimestamp = go'' $ \x st -> st { cachedTimestamp = Just x }
    go' CachedSnapshot  = go'' $ \x st -> st { cachedSnapshot  = Just x }
    go' CachedMirrors   = go'' $ \x st -> st { cachedMirrors   = Just x }

    go'' :: forall a. FromJSON ReadJSON_Keys_Layout a
         => (a -> LocalState -> LocalState) -> IO ()
    go'' f = do
      modifyMVar_ state $ \st@LocalState{..} -> do
        let keyEnv = rootKeys (signed cachedRoot)
        case parseJSON_Keys_Layout keyEnv cacheRepoLayout bs of
           Left  err    -> throwIO err
           Right parsed -> return $ f parsed st
