{-# LANGUAGE CPP #-}
module Main (main) where

import Control.Exception
import Control.Monad
import Data.List (nub)
import Data.Maybe (catMaybes, mapMaybe)
import Data.Time
import GHC.Conc.Sync (setUncaughtExceptionHandler)
import Network.URI (URI)
import System.Exit
import System.IO.Error (isAlreadyExistsError)
import qualified Data.ByteString.Lazy as BS.L
import qualified System.FilePath      as FilePath

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

-- hackage-security-utility
import Hackage.Security.Utility.Options
import Hackage.Security.Utility.Layout
import Hackage.Security.Utility.Util.IO
import Text.JSON.Canonical (JSValue)

{-------------------------------------------------------------------------------
  Main application driver
-------------------------------------------------------------------------------}

main :: IO ()
main = do
    setUncaughtExceptionHandler topLevelExceptionHandler
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      CreateKeys keysLoc ->
        createKeys opts keysLoc
      Bootstrap keysLoc repoLoc ->
        bootstrapOrUpdate opts keysLoc repoLoc True
      Update keysLoc repoLoc ->
        bootstrapOrUpdate opts keysLoc repoLoc False
      CreateRoot keysLoc rootLoc ->
        createRoot opts keysLoc rootLoc
      CreateMirrors keysLoc mirrorsLoc mirrors ->
        createMirrors opts keysLoc mirrorsLoc mirrors
      SymlinkCabalLocalRepo repoLoc cabalRepoLoc ->
        symlinkCabalLocalRepo opts repoLoc cabalRepoLoc
      Sign keys deleteExisting file ->
        signFile keys deleteExisting file

-- | Top-level exception handler that uses 'displayException'
--
-- Although base 4.8 introduces 'displayException', the top-level exception
-- handler still uses 'show', sadly. See "PROPOSAL: Add displayException to
-- Exception typeclass" thread on the libraries mailing list.
--
-- NOTE: This is a terrible hack. See the above thread for some insights into
-- how we should do this better. For now it will do however.
topLevelExceptionHandler :: SomeException -> IO ()
topLevelExceptionHandler e = do
    putStrLn $ displayException e
    exitFailure

#if !MIN_VERSION_base(4,8,0)
displayException :: Exception e => e -> String
displayException = show
#endif

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKeys :: GlobalOpts -> KeysLoc -> IO ()
createKeys opts keysLoc = do
    privateRoot      <- replicateM 3 $ createKey' KeyTypeEd25519
    privateTarget    <- replicateM 3 $ createKey' KeyTypeEd25519
    privateTimestamp <- replicateM 1 $ createKey' KeyTypeEd25519
    privateSnapshot  <- replicateM 1 $ createKey' KeyTypeEd25519
    privateMirrors   <- replicateM 3 $ createKey' KeyTypeEd25519
    writeKeys opts keysLoc PrivateKeys{..}

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

readKeys :: GlobalOpts -> KeysLoc -> IO PrivateKeys
readKeys opts keysLoc =
    PrivateKeys <$> readKeysAt opts keysLoc keysLayoutRoot
                <*> readKeysAt opts keysLoc keysLayoutTarget
                <*> readKeysAt opts keysLoc keysLayoutTimestamp
                <*> readKeysAt opts keysLoc keysLayoutSnapshot
                <*> readKeysAt opts keysLoc keysLayoutMirrors

writeKeys :: GlobalOpts -> KeysLoc -> PrivateKeys -> IO ()
writeKeys opts keysLoc PrivateKeys{..} = do
    forM_ privateRoot      $ writeKey opts keysLoc keysLayoutRoot
    forM_ privateTarget    $ writeKey opts keysLoc keysLayoutTarget
    forM_ privateTimestamp $ writeKey opts keysLoc keysLayoutTimestamp
    forM_ privateSnapshot  $ writeKey opts keysLoc keysLayoutSnapshot
    forM_ privateMirrors   $ writeKey opts keysLoc keysLayoutMirrors

readKeysAt :: GlobalOpts -> KeysLoc -> (KeysLayout -> KeyPath) -> IO [Some Key]
readKeysAt opts@GlobalOpts{..} keysLoc subDir = catMaybes <$> do
    entries <- getDirectoryContents absPath
    forM entries $ \entry -> do
      let path = absPath </> entry
      mKey <- readJSON_NoKeys_NoLayout path
      case mKey of
        Left _err -> do logWarn opts $ "Skipping unrecognized " ++ pretty path
                        return Nothing
        Right key -> return $ Just key
  where
    absPath = anchorKeyPath globalKeysLayout keysLoc subDir

writeKey :: GlobalOpts -> KeysLoc -> (KeysLayout -> KeyPath) -> Some Key -> IO ()
writeKey opts@GlobalOpts{..} keysLoc subDir key = do
    logInfo opts $ "Writing " ++ pretty (relPath globalKeysLayout)
    createDirectoryIfMissing True (takeDirectory absPath)
    writeJSON_NoLayout absPath key
  where
    relPath = keysLayoutKey subDir key
    absPath = anchorKeyPath globalKeysLayout keysLoc relPath

{-------------------------------------------------------------------------------
  Creating individual files

  We translate absolute paths to repo layout to fit with rest of infrastructure.
-------------------------------------------------------------------------------}

createRoot :: GlobalOpts -> KeysLoc -> Path Absolute -> IO ()
createRoot opts@GlobalOpts{..} keysLoc rootLoc = do
    keys <- readKeys opts keysLoc
    now  <- getCurrentTime
    updateRoot opts { globalRepoLayout = layout }
               repoLoc
               WriteUpdate
               keys
               now
  where
    repoLoc = RepoLoc $ takeDirectory rootLoc
    layout  = globalRepoLayout {
                  repoLayoutRoot = rootFragment $ takeFileName rootLoc
                }

createMirrors :: GlobalOpts -> KeysLoc -> Path Absolute -> [URI] -> IO ()
createMirrors opts@GlobalOpts{..} keysLoc mirrorsLoc mirrors = do
    keys <- readKeys opts keysLoc
    now  <- getCurrentTime
    updateMirrors opts { globalRepoLayout = layout }
                  repoLoc
                  WriteUpdate
                  keys
                  now
                  mirrors
  where
    repoLoc = RepoLoc $ takeDirectory mirrorsLoc
    layout  = globalRepoLayout {
                  repoLayoutMirrors = rootFragment $ takeFileName mirrorsLoc
                }

rootFragment :: String -> RepoPath
rootFragment = rootPath . fragment

{-------------------------------------------------------------------------------
  Bootstrapping / updating

  TODO: Some of this functionality should be moved to
  @Hackage.Security.Server.*@ (to be shared by both, say, Hackage, and
  secure-local),  but I'm not sure precisely in what form yet.
-------------------------------------------------------------------------------}

bootstrapOrUpdate :: GlobalOpts -> KeysLoc -> RepoLoc -> Bool -> IO ()
bootstrapOrUpdate opts@GlobalOpts{..} keysLoc repoLoc isBootstrap = do
    -- Collect info
    keys <- readKeys opts keysLoc
    now  <- getCurrentTime
    pkgs <- findPackages opts repoLoc

    -- Sanity check
    repoLayoutOk <- checkRepoLayout opts repoLoc pkgs
    unless repoLayoutOk $
      throwIO $ userError "Unexpected repository layout"

    -- We overwrite files during bootstrap process, but update them only
    -- if necessary during an update. Note that we _only_ write the updated
    -- files to the tarball, so the user deletes the tarball and then calls
    -- update (rather than bootstrap) the tarball will be missing files.
    let whenWrite = if isBootstrap
                      then WriteInitial
                      else WriteUpdate

    -- If doing bootstrap: create root and mirrors
    when isBootstrap $ do
      updateRoot    opts repoLoc whenWrite keys now
      updateMirrors opts repoLoc whenWrite keys now []

    -- Create targets.json for each package version
    forM_ pkgs $ \pkgId -> do
      createPackageMetadata opts repoLoc whenWrite pkgId
      extractCabalFile      opts repoLoc whenWrite pkgId

    -- Recreate index tarball
    newFiles <- findNewIndexFiles opts repoLoc whenWrite
    case (whenWrite, null newFiles) of
      (WriteInitial, _) -> do
        -- If we are recreating all files, also recreate the index
        _didExist <- handleDoesNotExist $ removeFile pathIndexTar
        logInfo opts $ "Writing " ++ prettyRepo repoLayoutIndexTar
      (WriteUpdate, True) -> do
        logInfo opts $ "Skipping " ++ prettyRepo repoLayoutIndexTar
      (WriteUpdate, False) ->
        logInfo opts $ "Appending " ++ show (length newFiles)
                    ++ " file(s) to " ++ prettyRepo repoLayoutIndexTar
    unless (null newFiles) $ do
      tarAppend
        (anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexTar)
        (anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexDir)
        (map castRoot newFiles)

      logInfo opts $ "Writing " ++ prettyRepo repoLayoutIndexTarGz
      compress (anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexTar)
               (anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexTarGz)

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
               repoLoc
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
               repoLoc
               whenWrite
               (InRep repoLayoutTimestamp)
               (withSignatures globalRepoLayout (privateTimestamp keys))
               timestamp
  where
    pathIndexTar :: Path Absolute
    pathIndexTar = anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexTar

    -- | Compute file information for a file in the repo
    computeFileInfo' :: (RepoLayout -> RepoPath) -> IO FileInfo
    computeFileInfo' = computeFileInfo . anchorRepoPath globalRepoLayout repoLoc

    prettyRepo :: (RepoLayout -> RepoPath) -> String
    prettyRepo = prettyTargetPath' globalRepoLayout . InRep

-- | Create root metadata
updateRoot :: GlobalOpts
           -> RepoLoc
           -> WhenWrite
           -> PrivateKeys
           -> UTCTime
           -> IO ()
updateRoot opts repoLoc whenWrite keys now =
    updateFile opts
               repoLoc
               whenWrite
               (InRep repoLayoutRoot)
               (withSignatures' (privateRoot keys))
               root
  where
    root :: Root
    root = Root {
        rootVersion = versionInitial
      , rootExpires = expiresInDays now (globalExpireRoot opts * 365)
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

-- | Create root metadata
updateMirrors :: GlobalOpts
              -> RepoLoc
              -> WhenWrite
              -> PrivateKeys
              -> UTCTime
              -> [URI]
              -> IO ()
updateMirrors opts repoLoc whenWrite keys now uris =
    updateFile opts
               repoLoc
               whenWrite
               (InRep repoLayoutMirrors)
               (withSignatures' (privateMirrors keys))
               mirrors
  where
    mirrors :: Mirrors
    mirrors = Mirrors {
        mirrorsVersion = versionInitial
      , mirrorsExpires = expiresInDays now (globalExpireMirrors opts * 365)
      , mirrorsMirrors = map mkMirror uris
      }

    mkMirror :: URI -> Mirror
    mkMirror uri = Mirror uri MirrorFull

-- | Create package metadata
createPackageMetadata :: GlobalOpts -> RepoLoc -> WhenWrite -> PackageIdentifier -> IO ()
createPackageMetadata opts@GlobalOpts{..} repoLoc whenWrite pkgId = do
    srcTS <- getFileModTime opts repoLoc src
    dstTS <- getFileModTime opts repoLoc dst
    let skip = case whenWrite of
                 WriteInitial -> False
                 WriteUpdate  -> dstTS >= srcTS

    if skip
      then logInfo opts $ "Skipping " ++ prettyTargetPath' globalRepoLayout dst
      else do
        fileMapEntries <- mapM computeFileMapEntry fileMapFiles
        let targets = Targets {
                targetsVersion     = versionInitial
              , targetsExpires     = expiresNever
              , targetsTargets     = FileMap.fromList fileMapEntries
              , targetsDelegations = Nothing
              }

        -- Currently we "sign" with no keys
        updateFile opts
                   repoLoc
                   whenWrite
                   dst
                   (withSignatures' [])
                   targets
  where
    computeFileMapEntry :: TargetPath' -> IO (TargetPath, FileInfo)
    computeFileMapEntry file = do
      info <- computeFileInfo $ anchorTargetPath' globalRepoLayout repoLoc file
      return (applyTargetPath' globalRepoLayout file, info)

    -- The files we need to add to the package targets file
    -- Currently this is just the .tar.gz file
    fileMapFiles :: [TargetPath']
    fileMapFiles = [src]

    src, dst :: TargetPath'
    src = InRepPkg repoLayoutPkgTarGz     pkgId
    dst = InIdxPkg indexLayoutPkgMetadata pkgId

{-------------------------------------------------------------------------------
  Working with the index
-------------------------------------------------------------------------------}

-- | Find the files we need to add to the index
findNewIndexFiles :: GlobalOpts -> RepoLoc -> WhenWrite -> IO [IndexPath]
findNewIndexFiles opts@GlobalOpts{..} repoLoc whenWrite = do
    indexTS    <- getFileModTime opts repoLoc (InRep repoLayoutIndexTar)
    indexFiles <- getRecursiveContents absIndexDir

    let indexFiles' :: [IndexPath]
        indexFiles' = map rootPath indexFiles

    case whenWrite of
      WriteInitial -> return indexFiles'
      WriteUpdate  -> liftM catMaybes $
        forM indexFiles' $ \indexFile -> do
          fileTS <- getFileModTime opts repoLoc $ InIdx (const indexFile)
          if fileTS > indexTS then return $ Just indexFile
                              else return Nothing
  where
    absIndexDir :: Path Absolute
    absIndexDir = anchorRepoPath globalRepoLayout repoLoc repoLayoutIndexDir

-- | Extract the cabal file from the package tarball and copy it to the index
extractCabalFile :: GlobalOpts -> RepoLoc -> WhenWrite -> PackageIdentifier -> IO ()
extractCabalFile opts@GlobalOpts{..} repoLoc whenWrite pkgId = do
    srcTS <- getFileModTime opts repoLoc src
    dstTS <- getFileModTime opts repoLoc dst
    let skip = case whenWrite of
                 WriteInitial -> False
                 WriteUpdate  -> dstTS >= srcTS
    if skip
      then logInfo opts $ "Skipping " ++ prettyTargetPath' globalRepoLayout dst
      else do
        mCabalFile <- try $ tarExtractFile opts repoLoc src pathCabalInTar
        case mCabalFile of
          Left (ex :: SomeException) ->
            logWarn opts $ "Failed to extract .cabal from package " ++ display pkgId
                        ++ ": " ++ displayException ex
          Right Nothing ->
            logWarn opts $ ".cabal file missing for package " ++ display pkgId
          Right (Just (cabalFile, _cabalSize)) -> do
            logInfo opts $ "Writing "
                        ++ prettyTargetPath' globalRepoLayout dst
                        ++ " (extracted from "
                        ++ prettyTargetPath' globalRepoLayout src
                        ++ ")"
            withFile pathCabalInIdx WriteMode $ \h -> BS.L.hPut h cabalFile
  where
    pathCabalInTar :: FilePath
    pathCabalInTar = FilePath.joinPath [
                         display pkgId
                       , display (packageName pkgId)
                       ] FilePath.<.> "cabal"

    pathCabalInIdx :: Path Absolute
    pathCabalInIdx = anchorTargetPath' globalRepoLayout repoLoc dst

    src, dst :: TargetPath'
    dst = InIdxPkg indexLayoutPkgCabal pkgId
    src = InRepPkg repoLayoutPkgTarGz  pkgId

{-------------------------------------------------------------------------------
  Updating files in the repo or in the index
-------------------------------------------------------------------------------}

data WhenWrite =
    -- | Write the initial version of a file
    --
    -- If applicable, set file version to 1.
    WriteInitial

    -- | Update an existing
    --
    -- If applicable, increment file version number.
  | WriteUpdate

-- | Write canonical JSON
--
-- We write the file to a temporary location and compare file info with the file
-- that was already in the target location (if any). If it's the same (modulo
-- version number) we don't overwrite it and return Nothing; otherwise we
-- increment the version number, write the file, and (if it's in the index)
-- copy it to the unpacked index directory.
updateFile :: forall a. (ToJSON WriteJSON (Signed a), HasHeader a)
           => GlobalOpts
           -> RepoLoc
           -> WhenWrite
           -> TargetPath'
           -> (a -> Signed a)          -- ^ Signing function
           -> a                        -- ^ Unsigned file contents
           -> IO ()
updateFile opts@GlobalOpts{..} repoLoc whenWrite fileLoc signPayload a = do
    mOldHeader :: Maybe (Either DeserializationError (UninterpretedSignatures Header)) <-
      handleDoesNotExist $ readJSON_NoKeys_NoLayout fp

    case (whenWrite, mOldHeader) of
      (WriteInitial, _) ->
        writeDoc writing a
      (WriteUpdate, Nothing) -> -- no previous version
        writeDoc creating a
      (WriteUpdate, Just (Left _err)) -> -- old file corrupted
        writeDoc overwriting a
      (WriteUpdate, Just (Right (UninterpretedSignatures oldHeader _oldSigs))) -> do
        -- We cannot quite read the entire old file, because we don't know what
        -- key environment to use. Instead, we render the _new_ file, but
        -- setting the version number to be equal to the version number of the
        -- old file. If the result turns out to be equal to the old file (same
        -- FileInfo), we skip writing this file. However, if this is NOT equal,
        -- we set the version number of the new file to be equal to the version
        -- number of the old plus one, and write it.
        oldFileInfo <- computeFileInfo fp

        let oldVersion :: FileVersion
            oldVersion = headerVersion oldHeader

            wOldVersion, wIncVersion :: a
            wOldVersion = Lens.set fileVersion oldVersion a
            wIncVersion = Lens.set fileVersion (versionIncrement oldVersion) a

            wOldSigned :: Signed a
            wOldSigned = signPayload wOldVersion

            wOldRendered :: BS.L.ByteString
            wOldRendered = renderJSON globalRepoLayout wOldSigned

            -- TODO: We could be be more efficient here and verify file size
            -- first; however, these files are tiny so it doesn't really matter.
            wOldFileInfo :: FileInfo
            wOldFileInfo = fileInfo wOldRendered

        if knownFileInfoEqual oldFileInfo wOldFileInfo
          then logInfo opts $ "Unchanged " ++ prettyTargetPath' globalRepoLayout fileLoc
          else writeDoc updating wIncVersion
  where
    -- | Actually write the file
    writeDoc :: String -> a -> IO ()
    writeDoc reason doc = do
      logInfo opts reason
      createDirectoryIfMissing True (takeDirectory fp)
      writeJSON globalRepoLayout fp (signPayload doc)

    fp :: Path Absolute
    fp = anchorTargetPath' globalRepoLayout repoLoc fileLoc

    writing, creating, overwriting, updating :: String
    writing     = "Writing "     ++ prettyTargetPath' globalRepoLayout fileLoc
    creating    = "Creating "    ++ prettyTargetPath' globalRepoLayout fileLoc
    overwriting = "Overwriting " ++ prettyTargetPath' globalRepoLayout fileLoc ++ " (old file corrupted)"
    updating    = "Updating "    ++ prettyTargetPath' globalRepoLayout fileLoc

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
findPackages :: GlobalOpts -> RepoLoc -> IO [PackageIdentifier]
findPackages GlobalOpts{..} (RepoLoc repoLoc) =
    nub . mapMaybe isPackage <$> getRecursiveContents repoLoc
  where
    isPackage :: Path Unrooted -> Maybe PackageIdentifier
    isPackage path = do
      guard $ not (isIndex path)
      pkg <- hasExtensions path [".tar", ".gz"]
      simpleParse pkg

    isIndex :: Path Unrooted -> Bool
    isIndex = (==) (unrootPath (repoLayoutIndexTarGz globalRepoLayout))

-- | Check that packages are in their expected location
checkRepoLayout :: GlobalOpts -> RepoLoc -> [PackageIdentifier] -> IO Bool
checkRepoLayout opts@GlobalOpts{..} repoLoc = liftM and . mapM checkPackage
  where
    checkPackage :: PackageIdentifier -> IO Bool
    checkPackage pkgId = do
        existsTarGz <- doesFileExist $ anchorTargetPath' globalRepoLayout repoLoc expectedTarGz
        unless existsTarGz $
          logWarn opts $ "Package tarball " ++ display pkgId
                      ++ " expected in location "
                      ++ prettyTargetPath' globalRepoLayout expectedTarGz

        return existsTarGz
      where
        expectedTarGz :: TargetPath'
        expectedTarGz = InRepPkg repoLayoutPkgTarGz pkgId

{-------------------------------------------------------------------------------
  Creating Cabal-local-repo
-------------------------------------------------------------------------------}

symlinkCabalLocalRepo :: GlobalOpts -> RepoLoc -> RepoLoc -> IO ()
symlinkCabalLocalRepo opts@GlobalOpts{..} repoLoc cabalRepoLoc = do
    symlink repoLayoutIndexTar
    pkgs <- findPackages opts repoLoc
    forM_ pkgs $ \pkgId -> symlink (`repoLayoutPkgTarGz` pkgId)
  where
    -- TODO: This gives a warning for files that we previously linked, as well
    -- as for files that we _never_ need to link (because the location of both
    -- repos is the same). This is potentially confusing.
    symlink :: (RepoLayout -> RepoPath) -> IO ()
    symlink file =
        catch (createSymbolicLink target loc) $ \ex ->
          if isAlreadyExistsError ex
            then logWarn opts $ "Skipping " ++ pretty (file globalRepoLayout)
                             ++ " (already exists)"
            else throwIO ex
      where
        target = anchorRepoPath globalRepoLayout     repoLoc      file
        loc    = anchorRepoPath cabalLocalRepoLayout cabalRepoLoc file

{-------------------------------------------------------------------------------
  Signing individual files
-------------------------------------------------------------------------------}

signFile :: [KeyLoc] -> DeleteExistingSignatures -> Path Absolute -> IO ()
signFile keyLocs deleteExisting fp = do
    UninterpretedSignatures (payload :: JSValue) oldSigs <-
      throwErrors =<< readJSON_NoKeys_NoLayout fp
    keys :: [Some Key] <- forM keyLocs $ \keyLoc ->
      throwErrors =<< readJSON_NoKeys_NoLayout keyLoc
    let newSigs = concat [
            if deleteExisting then [] else oldSigs
          , toPreSignatures (signRendered keys $ renderJSON_NoLayout payload)
          ]
    writeJSON_NoLayout fp $ UninterpretedSignatures payload newSigs

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
hasExtensions = \fp exts -> go (takeFileName fp) (reverse exts)
  where
    go :: FilePath -> [String] -> Maybe String
    go fp []     = return fp
    go fp (e:es) = do let (fp', e') = FilePath.splitExtension fp
                      guard $ e == e'
                      go fp' es

throwErrors :: Exception e => Either e a -> IO a
throwErrors (Left err) = throwIO err
throwErrors (Right a)  = return a
