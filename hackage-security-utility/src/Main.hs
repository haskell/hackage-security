{-# LANGUAGE TemplateHaskell #-}
module Main (main) where

import Control.Exception
import Control.Monad
import Data.Maybe (catMaybes, mapMaybe)
import Data.Time
import System.IO
import System.IO.Error
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Entry as Tar
import qualified Codec.Compression.GZip  as GZip
import qualified Data.ByteString.Lazy    as BS.L
import qualified System.FilePath         as FilePath

-- Unlike the hackage-security library properly,
-- this currently works on unix systems only
import System.Posix.Files (getFileStatus, modificationTime)
import System.Posix.Types (EpochTime)

-- Cabal
import Distribution.Package
import Distribution.Text

-- hackage-security
import Hackage.Security.Server
import Hackage.Security.Util.Some
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import qualified Hackage.Security.Key.Env     as KeyEnv
import qualified Hackage.Security.TUF.FileMap as FileMap
import qualified Hackage.Security.Util.Lens   as Lens

-- hackage-secure-local
import Hackage.Security.Utility.Options
import Hackage.Security.Utility.Layout

{-------------------------------------------------------------------------------
  Main application driver
-------------------------------------------------------------------------------}

main :: IO ()
main = do
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      CreateKeys -> createKeys opts
      Bootstrap  -> bootstrapOrUpdate opts True
      Update     -> bootstrapOrUpdate opts False

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKeys :: GlobalOpts -> IO ()
createKeys opts = do
    privateRoot      <- replicateM 3 $ createKey' KeyTypeEd25519
    privateTarget    <- replicateM 3 $ createKey' KeyTypeEd25519
    privateTimestamp <- replicateM 1 $ createKey' KeyTypeEd25519
    privateSnapshot  <- replicateM 1 $ createKey' KeyTypeEd25519
    privateMirrors   <- replicateM 3 $ createKey' KeyTypeEd25519
    writeKeys opts PrivateKeys{..}

{-------------------------------------------------------------------------------
  Dealing with (private) keys
-------------------------------------------------------------------------------}

data PrivateKeys = PrivateKeys {
    privateRoot      :: [Some Key]
  , privateTarget    :: [Some Key]
  , privateTimestamp :: [Some Key]
  , privateSnapshot  :: [Some Key]
  , privateMirrors   :: [Some Key]
  }

readKeys :: GlobalOpts -> IO PrivateKeys
readKeys opts =
    PrivateKeys <$> readKeysAt opts keyLayoutRoot
                <*> readKeysAt opts keyLayoutTarget
                <*> readKeysAt opts keyLayoutTimestamp
                <*> readKeysAt opts keyLayoutSnapshot
                <*> readKeysAt opts keyLayoutMirrors

writeKeys :: GlobalOpts -> PrivateKeys -> IO ()
writeKeys opts PrivateKeys{..} = do
    forM_ privateRoot      $ writeKey opts keyLayoutRoot
    forM_ privateTarget    $ writeKey opts keyLayoutTarget
    forM_ privateTimestamp $ writeKey opts keyLayoutTimestamp
    forM_ privateSnapshot  $ writeKey opts keyLayoutSnapshot
    forM_ privateMirrors   $ writeKey opts keyLayoutMirrors

readKeysAt :: GlobalOpts -> (KeyLayout -> KeyPath) -> IO [Some Key]
readKeysAt opts keyDir = catMaybes <$> do
    entries <- getDirectoryContents absPath
    forM entries $ \entry -> do
      let path = absPath </> entry
      mKey <- readJSON_NoKeys_NoLayout path
      case mKey of
        Left _err -> do logWarn opts $ "Skipping unrecognized " ++ pretty path
                        return Nothing
        Right key -> return $ Just key
  where
    absPath = anchorKeyPath opts keyDir

writeKey :: GlobalOpts -> (KeyLayout -> KeyPath) -> Some Key -> IO ()
writeKey opts keyDir key = do
    logInfo opts $ "Writing " ++ pretty (relPath defaultKeyLayout)
    createDirectoryIfMissing True (takeDirectory absPath)
    writeJSON_NoLayout absPath key
  where
    relPath = keyLayoutKey keyDir key
    absPath = anchorKeyPath opts relPath

{-------------------------------------------------------------------------------
  Bootstrapping / updating

  TODO: Some of this functionality should be moved to
  @Hackage.Security.Server.*@ (to be shared by both, say, Hackage, and
  secure-local),  but I'm not sure precisely in what form yet.
-------------------------------------------------------------------------------}

bootstrapOrUpdate :: GlobalOpts -> Bool -> IO ()
bootstrapOrUpdate opts@GlobalOpts{..} isBootstrap = do
    -- Collect info
    keys <- readKeys opts
    now  <- getCurrentTime
    pkgs <- findPackages opts

    -- Sanity check
    repoLayoutOk <- checkRepoLayout opts pkgs
    unless repoLayoutOk $
      throwIO $ userError "Unexpected repository layout"

    -- We overwrite files during bootstrap process, but update them only
    -- if necessary during an update. Note that we _only_ write the updated
    -- files to the tarball, so the user deletes the tarball and then calls
    -- update (rather than bootstrap) the tarball will be missing files.
    let whenWrite = if isBootstrap
                      then WriteAlways
                      else WriteIfNecessary

    -- If doing bootstrap: create root, mirrors, and top-level target files
    when isBootstrap $ do
      -- Create root metadata
      let root = Root {
              rootVersion = versionInitial
            , rootExpires = expiresInDays now 365
            , rootKeys    = KeyEnv.fromKeys $ concat [
                                privateRoot      keys
                              , privateTarget    keys
                              , privateSnapshot  keys
                              , privateTimestamp keys
                              , privateMirrors   keys
                              ]
            , rootRoles   = RootRoles {
                  rootRolesRoot = RoleSpec {
                      roleSpecKeys      = map somePublicKey (privateRoot keys)
                    , roleSpecThreshold = KeyThreshold 2
                    }
                , rootRolesTargets = RoleSpec {
                      roleSpecKeys      = map somePublicKey (privateTarget keys)
                    , roleSpecThreshold = KeyThreshold 1
                    }
                , rootRolesSnapshot = RoleSpec {
                      roleSpecKeys      = map somePublicKey (privateSnapshot keys)
                    , roleSpecThreshold = KeyThreshold 1
                    }
                , rootRolesTimestamp = RoleSpec {
                      roleSpecKeys      = map somePublicKey (privateTimestamp keys)
                    , roleSpecThreshold = KeyThreshold 1
                    }
                , rootRolesMirrors = RoleSpec {
                      roleSpecKeys      = map somePublicKey (privateMirrors keys)
                    , roleSpecThreshold = KeyThreshold 1
                    }
                }
            }

      updateFile opts
                 whenWrite
                 (InRep repoLayoutRoot)
                 (withSignatures' (privateRoot keys))
                 root

      -- Create mirrors
      let mkMirror uri = Mirror uri MirrorFull
      let mirrors = Mirrors {
              mirrorsVersion = versionInitial
            , mirrorsExpires = expiresInDays now (10 * 365)
            , mirrorsMirrors = map mkMirror globalMirrors
            }
      updateFile opts
                 whenWrite
                 (InRep repoLayoutMirrors)
                 (withSignatures' (privateMirrors keys))
                 mirrors

    -- Create targets.json for each package version
    forM_ pkgs $ createPackageMetadata opts whenWrite

    -- Recreate index tarball
    newFiles <- findNewIndexFiles opts whenWrite
    case (whenWrite, null newFiles) of
      (WriteAlways, _) -> do
        -- If we are recreating all files, also recreate the index
        _didExist <- handleDoesNotExist $ removeFile pathIndexTar
        logInfo opts $ "Writing " ++ prettyTargetPath' opts (InRep repoLayoutIndexTar)
      (WriteIfNecessary, True) -> do
        logInfo opts $ "Skipping " ++ prettyTargetPath' opts (InRep repoLayoutIndexTar)
      (WriteIfNecessary, False) ->
        logInfo opts $ "Appending " ++ show (length newFiles)
                    ++ " file(s) to " ++ prettyTargetPath' opts (InRep repoLayoutIndexTar)
    unless (null newFiles) $ do
      tarAppend
        (anchorRepoPath opts repoLayoutIndexTar)
        (anchorRepoPath opts repoLayoutIndexDir)
        (map castRoot newFiles)

      logInfo opts $ "Writing " ++ prettyTargetPath' opts (InRep repoLayoutIndexTarGz)
      compress (anchorRepoPath opts repoLayoutIndexTar)
               (anchorRepoPath opts repoLayoutIndexTarGz)

    -- Create snapshot
    -- TODO: If we are updating we should be incrementing the version, not
    -- keeping it the same
    rootInfo    <- computeFileInfo' repoLayoutRoot
    mirrorsInfo <- computeFileInfo' repoLayoutMirrors
    tarInfo     <- computeFileInfo' repoLayoutIndexTar
    tarGzInfo   <- computeFileInfo' repoLayoutIndexTarGz
    let snapshot = Snapshot {
            snapshotVersion     = versionInitial
          , snapshotExpires     = expiresInDays now 3
          , snapshotInfoRoot    = rootInfo
          , snapshotInfoMirrors = mirrorsInfo
          , snapshotInfoTar     = Just tarInfo
          , snapshotInfoTarGz   = tarGzInfo
          }
    updateFile opts
               whenWrite
               (InRep repoLayoutSnapshot)
               (withSignatures globalRepoLayout (privateSnapshot keys))
               snapshot

    -- Finally, create the timestamp
    snapshotInfo <- computeFileInfo' repoLayoutSnapshot
    let timestamp = Timestamp {
            timestampVersion      = versionInitial
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = snapshotInfo
          }
    updateFile opts
               whenWrite
               (InRep repoLayoutTimestamp)
               (withSignatures globalRepoLayout (privateTimestamp keys))
               timestamp
  where
    pathIndexTar :: AbsolutePath
    pathIndexTar = anchorRepoPath opts repoLayoutIndexTar

    -- | Compute file information for a file in the repo
    computeFileInfo' :: (RepoLayout -> RepoPath) -> IO FileInfo
    computeFileInfo' = computeFileInfo . anchorRepoPath opts

-- | Create package metadata
createPackageMetadata :: GlobalOpts -> WhenWrite -> PackageIdentifier -> IO ()
createPackageMetadata opts whenWrite pkgId = do
    fileMapEntries <- mapM computeFileMapEntry fileMapFiles
    let targets = Targets {
            targetsVersion     = versionInitial
          , targetsExpires     = expiresNever
          , targetsTargets     = FileMap.fromList fileMapEntries
          , targetsDelegations = Nothing
          }

    -- Currently we "sign" with no keys
    updateFile opts
               whenWrite
               (InIdxPkg indexLayoutPkgMetadata pkgId)
               (withSignatures' [])
               targets

    -- Extract the cabal file from the package tarball and copy it to the index
    extractCabalFile opts whenWrite pkgId
  where
    computeFileMapEntry :: TargetPath' -> IO (TargetPath, FileInfo)
    computeFileMapEntry file = do
      info <- computeFileInfo (anchorTargetPath' opts file)
      return (applyTargetPath' opts file, info)

    -- The files we need to add to the package targets file
    -- Currently this is just the .tar.gz file
    fileMapFiles :: [TargetPath']
    fileMapFiles = [
        InRepPkg repoLayoutPkgTarGz pkgId
      ]

{-------------------------------------------------------------------------------
  Working with the index
-------------------------------------------------------------------------------}

-- | Find the files we need to add to the index
findNewIndexFiles :: GlobalOpts -> WhenWrite -> IO [IndexPath]
findNewIndexFiles opts whenWrite = do
    indexTS    <- getFileModificationTime $ anchorRepoPath opts repoLayoutIndexTar
    indexFiles <- getRecursiveContents    $ anchorRepoPath opts repoLayoutIndexDir

    let indexFiles' :: [IndexPath]
        indexFiles' = map (rootPath Rooted) indexFiles

    case whenWrite of
      WriteAlways      -> return indexFiles'
      WriteIfNecessary -> liftM catMaybes $
        forM indexFiles' $ \indexFile -> do
          fileTS <- getFileModificationTime $ anchorIndexPath opts (const indexFile)
          if fileTS > indexTS then return $ Just indexFile
                              else return Nothing

-- | Extract the cabal file from the package tarball and copy it to the index
extractCabalFile :: GlobalOpts -> WhenWrite -> PackageIdentifier -> IO ()
extractCabalFile opts@GlobalOpts{..} whenWrite pkgId = do
    tarGzTS <- getFileModificationTime pathTarGz
    cabalTS <- getFileModificationTime pathCabalInIdx
    let skip = case whenWrite of
                 WriteAlways      -> False
                 WriteIfNecessary -> cabalTS >= tarGzTS
    if skip
      then logInfo opts $ "Skipping " ++ prettyTargetPath' opts dst
      else do
        archive <- Tar.read . GZip.decompress <$> readLazyByteString pathTarGz
        mCabalFile <- tarExtractFile pathCabalInTar archive
        case mCabalFile of
          Nothing ->
            logWarn opts $ ".cabal file missing for package " ++ display pkgId
          Just (cabalFile, _cabalSize) -> do
            logInfo opts $ "Writing "
                        ++ prettyTargetPath' opts dst
                        ++ " (extracted from "
                        ++ prettyTargetPath' opts src
                        ++ ")"
            writeLazyByteString pathCabalInIdx cabalFile
  where
    pathCabalInTar :: FilePath
    pathCabalInTar = FilePath.joinPath [
                         display pkgId
                       , display (packageName pkgId)
                       ] FilePath.<.> "cabal"

    pathTarGz, pathCabalInIdx :: AbsolutePath
    pathCabalInIdx = anchorTargetPath' opts dst
    pathTarGz      = anchorTargetPath' opts src

    src, dst :: TargetPath'
    dst = InIdxPkg indexLayoutPkgCabal pkgId
    src = InRepPkg repoLayoutPkgTarGz  pkgId

{-------------------------------------------------------------------------------
  Updating files in the repo or in the index
-------------------------------------------------------------------------------}

data WhenWrite = WriteIfNecessary | WriteAlways

-- | Write canonical JSON
--
-- We write the file to a temporary location and compare file info with the file
-- that was already in the target location (if any). If it's the same (modulo
-- version number) we don't overwrite it and return Nothing; otherwise we
-- increment the version number, write the file, and (if it's in the index)
-- copy it to the unpacked index directory.
--
-- TODO: This currently uses withSystemTempFile, which means that 'renameFile'
-- might not work. Instead we should (here and elsewhere) have a temporary
-- directory on the same file system. A worry for later.
updateFile :: forall a. (ToJSON WriteJSON (Signed a), HasHeader a)
           => GlobalOpts
           -> WhenWrite
           -> TargetPath'
           -> (a -> Signed a)          -- ^ Signing function
           -> a                        -- ^ Unsigned file contents
           -> IO ()
updateFile opts@GlobalOpts{..} whenWrite fileLoc signPayload a = do
    mOldHeader :: Maybe (Either DeserializationError (IgnoreSigned Header)) <-
      handleDoesNotExist $ readJSON_NoKeys_NoLayout fp

    case (whenWrite, mOldHeader) of
      (WriteAlways, _) ->
        writeDoc writing a
      (WriteIfNecessary, Nothing) -> -- no previous version
        writeDoc creating a
      (WriteIfNecessary, Just (Left _err)) -> -- old file corrupted
        writeDoc overwriting a
      (WriteIfNecessary, Just (Right (IgnoreSigned oldHeader))) -> do
        -- We cannot quite read the entire old file, because we don't know
        -- what key environment to use. Instead, we write the _new_ file,
        -- but setting the version number to be able to the version number
        -- of the old file. If this turns out to be equal to the old file, we
        -- skip writing this file. However, if this is NOT equal, we set the
        -- version number of the new file to be equal to the version number of
        -- the old plus one, and write the new file once more.

        let oldVersion  = headerVersion oldHeader
            wOldVersion = Lens.set fileVersion oldVersion a
            wIncVersion = Lens.set fileVersion (versionIncrement oldVersion) a

        withSystemTempFile (unFragment (takeFileName fp)) $ \tempPath h -> do
          -- Write new file, but using old file version
          BS.L.hPut h $ renderJSON globalRepoLayout (signPayload wOldVersion)
          hClose h

          -- Compare file hashes
          oldFileInfo <- computeFileInfo' fp
          newFileInfo <- computeFileInfo tempPath
          if oldFileInfo == Just newFileInfo
            then logInfo opts $ "Skipping " ++ prettyTargetPath' opts fileLoc
            else writeDoc updating wIncVersion
  where
    -- | Actually write the file
    writeDoc :: String -> a -> IO ()
    writeDoc reason doc = do
      logInfo opts reason
      createDirectoryIfMissing True (takeDirectory fp)
      writeJSON globalRepoLayout fp (signPayload doc)

    fp :: AbsolutePath
    fp = anchorTargetPath' opts fileLoc

    writing, creating, overwriting, updating :: String
    writing     = "Writing "     ++ prettyTargetPath' opts fileLoc
    creating    = "Creating "    ++ prettyTargetPath' opts fileLoc
    overwriting = "Overwriting " ++ prettyTargetPath' opts fileLoc ++ " (old file corrupted)"
    updating    = "Updating "    ++ prettyTargetPath' opts fileLoc

    computeFileInfo' :: AbsolutePath -> IO (Maybe FileInfo)
    computeFileInfo' path =
        handle doesNotExist $ Just <$> computeFileInfo path
      where
        doesNotExist e = if isDoesNotExistError e
                           then return Nothing
                           else throwIO e

{-------------------------------------------------------------------------------
  Inspect the repo layout
-------------------------------------------------------------------------------}

-- | Find packages
--
-- Repository layouts are configurable, but we don't know if the layout of the
-- current directory matches the specified layout. We therefore here just search
-- through the directory looking for anything that looks like a package.
-- We can then verify that this list of packages actually matches the layout as
-- a separate step.
findPackages :: GlobalOpts -> IO [PackageIdentifier]
findPackages GlobalOpts{..} =
    mapMaybe isPackage <$> getRecursiveContents globalRepo
  where
    isPackage :: UnrootedPath -> Maybe PackageIdentifier
    isPackage path = do
      guard $ not (isIndex path)
      pkg <- hasExtensions path [".tar", ".gz"]
      simpleParse pkg

    isIndex :: UnrootedPath -> Bool
    isIndex = (==) (unrootPath' (repoLayoutIndexTarGz globalRepoLayout))

-- | Check that packages are in their expected location
checkRepoLayout :: GlobalOpts -> [PackageIdentifier] -> IO Bool
checkRepoLayout opts@GlobalOpts{..} = liftM and . mapM checkPackage
  where
    checkPackage :: PackageIdentifier -> IO Bool
    checkPackage pkgId = do
        existsTarGz <- doesFileExist $ anchorTargetPath' opts expectedTarGz
        unless existsTarGz $
          logWarn opts $ "Package tarball " ++ display pkgId
                      ++ " expected in location "
                      ++ prettyTargetPath' opts expectedTarGz

        return existsTarGz
      where
        expectedTarGz :: TargetPath'
        expectedTarGz = InRepPkg repoLayoutPkgTarGz pkgId

{-------------------------------------------------------------------------------
  Logging
-------------------------------------------------------------------------------}

logInfo :: GlobalOpts -> String -> IO ()
logInfo GlobalOpts{..} str = when globalVerbose $
    putStrLn $ "Info: " ++ str

logWarn :: GlobalOpts -> String -> IO ()
logWarn _opts str =
    putStrLn $ "Warning: " ++ str

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Check that a file has the given extensions
--
-- Returns the filename without the verified extensions. For example:
--
-- > hasExtensions "foo.tar.gz" [".tar", ".gz"] == Just "foo"
hasExtensions :: Path a -> [String] -> Maybe String
hasExtensions = \fp exts -> go (takeFileName' fp) (reverse exts)
  where
    go :: FilePath -> [String] -> Maybe String
    go fp []     = return fp
    go fp (e:es) = do let (fp', e') = FilePath.splitExtension fp
                      guard $ e == e'
                      go fp' es

    takeFileName' :: Path a -> String
    takeFileName' = unFragment . takeFileName

-- | Get the modification time of the specified file
--
-- Returns 0 if the file does not exist .
getFileModificationTime :: AbsolutePath -> IO EpochTime
getFileModificationTime fp = handle handler $
    modificationTime <$> getFileStatus (toFilePath fp)
  where
    handler :: IOException -> IO EpochTime
    handler ex = if isDoesNotExistError ex then return 0
                                           else throwIO ex

compress :: AbsolutePath -> AbsolutePath -> IO ()
compress src dst =
    writeLazyByteString dst =<< GZip.compress <$> readLazyByteString src

-- | Extract a file from a tar archive
--
-- Throws an exception if there is an error in the archive or when the entry
-- is not a file. Returns nothing if the entry cannot be found.
tarExtractFile :: forall e. Exception e
               => FilePath
               -> Tar.Entries e
               -> IO (Maybe (BS.L.ByteString, Tar.FileSize))
tarExtractFile path = go
  where
    go :: Tar.Entries e -> IO (Maybe (BS.L.ByteString, Tar.FileSize))
    go Tar.Done        = return Nothing
    go (Tar.Fail err)  = throwIO err
    go (Tar.Next e es) =
      if Tar.entryPath e == path
        then case Tar.entryContent e of
               Tar.NormalFile bs sz -> return $ Just (bs, sz)
               _ -> throwIO $ userError "tarExtractFile: Not a normal file"
        else do -- putStrLn $ show (Tar.entryPath e) ++ " /= " ++ show path
                go es
