{-# LANGUAGE  ScopedTypeVariables #-}

module Main where

import Control.Concurrent
import Control.DeepSeq
import Control.Exception
import Control.Monad
import Data.Map.Strict (Map)
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
        precomputePkg state ("package " ++ init pkg) blobPath
      [_date, "candidates/", "package/", pkg, _pkgTarGz] -> do
        let blobPath = normalizePath (stateBackupDir state </> takeDirectory src </> dst)
        precomputePkg state ("candidate " ++ init pkg) blobPath
      _otherwise -> do
        return ()

precomputePkg :: State     -- ^ State to add the computed hash to
              -> String    -- ^ Package name (for reporting only)
              -> FilePath  -- ^ Location of the blob ID (ending in @../<md5>@)
              -> IO ()
precomputePkg state pkg dst = do
    putStr pkg
    let md5 = takeFileName dst
    alreadyKnown <- isKnownHash state md5
    if alreadyKnown
      then putStrLn " (skipped)"
      else do
        (sha256, len) <- withFile dst ReadMode $ \h -> do
          len    <- hFileSize h
          sha256 <- SHA.showDigest . SHA.sha256 <$> BS.L.hGetContents h
          evaluate $ rnf (sha256, len)
          return (sha256, len)
        recordHash state md5 sha256 len
        putStrLn " OK"

{-------------------------------------------------------------------------------
  State
-------------------------------------------------------------------------------}

type MD5    = String
type SHA256 = String
type Length = Integer

data State = State {
      -- | The directory where the backup is stored
      --
      -- This is necessary so we can resolve relative paths inside the tarball
      stateBackupDir :: FilePath

      -- | Mutable variable where we store the hashes computed so far
      --
      -- We use this so that even on CTRL-C we can still output a partial map
    , stateVar :: MVar (Map MD5 (SHA256, Length))
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

recordHash :: State -> MD5 -> SHA256 -> Length -> IO ()
recordHash State{..} md5 sha256 len =
    modifyMVar_ stateVar $ return . Map.insert md5 (sha256, len)

isKnownHash :: State -> MD5 -> IO Bool
isKnownHash State{..} md5 = withMVar stateVar $ return . Map.member md5

writeMap :: FilePath -> Map MD5 (SHA256, Length) -> IO ()
writeMap fp hashes = withFile fp WriteMode $ \h ->
    mapM_ (uncurry (writeEntry h)) $ Map.toList hashes
  where
    writeEntry :: Handle -> MD5 -> (SHA256, Length) -> IO ()
    writeEntry h md5 (sha256, len) =
        hPutStrLn h $ unwords [md5, sha256, show len]

-- | Read an existing hashmap
--
-- The result is guaranteed to be in normal form.
readMap :: FilePath -> IO (Map MD5 (SHA256, Length))
readMap fp =
    withFile fp ReadMode $ \h -> do
      hashes <- mapFromParseEntry . lines <$> hGetContents h
      evaluate $ rnf hashes
      return hashes
  where
    mapFromParseEntry :: [String] -> Map MD5 (SHA256, Length)
    mapFromParseEntry mapLines = Map.fromList
      [(md5, (sha256, read len)) | [md5, sha256, len] <- words <$> mapLines]

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
