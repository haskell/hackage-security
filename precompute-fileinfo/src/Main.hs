module Main where

import Control.Applicative
import Control.Concurrent
import Control.DeepSeq
import Control.Exception
import Control.Monad
import Data.Map.Strict (Map)
import Data.Monoid
import Options.Applicative
import System.FilePath
import System.IO
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Entry as Tar
import qualified Codec.Compression.GZip  as GZip
import qualified Data.ByteString.Lazy    as BS.L
import qualified Data.Digest.Pure.SHA    as SHA
import qualified Data.Map                as Map

{-------------------------------------------------------------------------------
  Main application driver
-------------------------------------------------------------------------------}

main :: IO ()
main = do
    options    <- getOptions
    tarEntries <- readTGz $ optionsArchive options
    state      <- initState options

    precomputeEntries state tarEntries `finally` writeState options state

{-------------------------------------------------------------------------------
  Command line options
-------------------------------------------------------------------------------}

data Options = Options {
      optionsInput   :: Maybe FilePath
    , optionsOutput  :: FilePath
    , optionsArchive :: FilePath
    }

parseOptions :: Parser Options
parseOptions = Options
  <$> (optional . strOption $ mconcat [
          short 'i'
        , long "input"
        , help "Input filename (if appending to existing map)"
        ])
  <*> (strOption $ mconcat [
          short 'o'
        , long "output"
        , help "Output filename"
        ])
  <*> argument str (metavar "ARCHIVE")

getOptions :: IO Options
getOptions = execParser opts
  where
    opts = info (helper <*> parseOptions) $ mconcat [
        fullDesc
      , progDesc "Precompute file info from a Hackage --hardlink-blobs backup"
      ]

{-------------------------------------------------------------------------------
  Core functionality
-------------------------------------------------------------------------------}

precomputeEntries :: Exception e => State -> Tar.Entries e -> IO ()
precomputeEntries state = go
  where
    go (Tar.Fail e)    = throwIO e
    go Tar.Done        = return ()
    go (Tar.Next e es) = precomputeEntry state e >> go es

precomputeEntry :: State -> Tar.Entry -> IO ()
precomputeEntry state entry =
    case Tar.entryContent entry of
      Tar.SymbolicLink linkTarget ->
        precomputeSymLink state
                          (Tar.entryPath entry)
                          (Tar.fromLinkTarget linkTarget)
      _otherwise ->
        return ()

precomputeSymLink :: State -> FilePath -> FilePath -> IO ()
precomputeSymLink state src dst =
    case splitPath src of
      [_date, "core/", "package/", pkg, _pkgTarGz] -> do
        let blobPath = normalizePath (stateBackupDir state </> takeDirectory src </> dst)
        precomputePkg state pkg blobPath
      _otherwise ->
        return ()

precomputePkg :: State -> String -> FilePath -> IO ()
precomputePkg state pkg dst = do
    putStr pkg
    let md5 = takeFileName dst
    alreadyKnown <- isKnownHash state md5
    if alreadyKnown
      then putStrLn " (skipped)"
      else do
        sha256 <- SHA.showDigest . SHA.sha256 <$> BS.L.readFile dst
        recordHash state md5 sha256
        putStrLn " OK"

{-------------------------------------------------------------------------------
  State
-------------------------------------------------------------------------------}

type MD5    = String
type SHA256 = String

data State = State {
      -- | The directory where the backup is stored
      --
      -- This is necessary so we can resolve relative paths inside the tarball
      stateBackupDir :: FilePath

      -- | Mutable variable where we store the hashes computed so far
      --
      -- We use this so that even on CTRL-C we can still output a partial map
    , stateVar :: MVar (Map MD5 SHA256)
    }

initState :: Options -> IO State
initState Options{..} = do
    initMap <- case optionsInput of
                 Nothing -> return Map.empty
                 Just fn -> readMap fn
    stateVar <- newMVar initMap
    return State{..}
  where
    stateBackupDir = takeDirectory optionsArchive

writeState :: Options -> State -> IO ()
writeState Options{..} State{..} = do
    putStrLn $ "Writing " ++ optionsOutput
    writeMap optionsOutput =<< readMVar stateVar

recordHash :: State -> MD5 -> SHA256 -> IO ()
recordHash State{..} md5 sha256 = do
    evaluate $ rnf (md5, sha256)
    modifyMVar_ stateVar $ return . Map.insert md5 sha256

isKnownHash :: State -> MD5 -> IO Bool
isKnownHash State{..} md5 = withMVar stateVar $ return . Map.member md5

writeMap :: FilePath -> Map MD5 SHA256 -> IO ()
writeMap fp hashes = withFile fp WriteMode $ \h ->
    mapM_ (uncurry (writeEntry h)) $ Map.toList hashes
  where
    writeEntry :: Handle -> MD5 -> SHA256 -> IO ()
    writeEntry h md5 sha256 = hPutStrLn h (md5 ++ " " ++ sha256)

-- | Read an existing hashmap
--
-- The result is guaranteed to be in normal form.
readMap :: FilePath -> IO (Map MD5 SHA256)
readMap fp = withFile fp ReadMode $ \h -> do
    hashes <- Map.fromList . map parseEntry . lines <$> hGetContents h
    evaluate $ rnf hashes
    return hashes
  where
    parseEntry :: String -> (MD5, SHA256)
    parseEntry line = let [md5, sha256] = words line in (md5, sha256)

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Change @a/b/c/d/e/../../../../f@ to @a/f@
normalizePath :: FilePath -> FilePath
normalizePath = joinPath . go . splitPath . normalise
  where
    go :: [String] -> [String]
    go [] = []
    go (d : ds) =
      case go ds of
        "../" : ds'' | d /= "../" -> ds''
        ds'                       -> d : ds'

readTGz :: FilePath -> IO (Tar.Entries Tar.FormatError)
readTGz = liftM (Tar.read . GZip.decompress) . BS.L.readFile
