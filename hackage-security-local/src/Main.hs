{-# LANGUAGE TemplateHaskell #-}
module Main (main) where

import Control.Exception
import Control.Monad
import Data.Maybe (catMaybes)
import Data.Time
import System.Directory ()
import System.IO
import System.IO.Error
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy   as BS.L

-- Cabal
import Distribution.Package
import Distribution.Text

-- hackage-security
import Hackage.Security.Server
import Hackage.Security.Util.Some
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path
import qualified Hackage.Security.Key.Env             as KeyEnv
import qualified Hackage.Security.Server.IndexTarball as Index
import qualified Hackage.Security.TUF.FileMap         as FileMap
import qualified Hackage.Security.Util.Lens           as Lens

-- hackage-secure-local
import Hackage.Security.Local.Options

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
readKeys GlobalOpts{..} =
    PrivateKeys <$> readKeysAt (globalKeys </> fragment "root")
                <*> readKeysAt (globalKeys </> fragment "target")
                <*> readKeysAt (globalKeys </> fragment "timestamp")
                <*> readKeysAt (globalKeys </> fragment "snapshot")
                <*> readKeysAt (globalKeys </> fragment "mirrors")

writeKeys :: GlobalOpts -> PrivateKeys -> IO ()
writeKeys opts PrivateKeys{..} = do
    forM_ privateRoot      $ writeKey opts "root"
    forM_ privateTarget    $ writeKey opts "target"
    forM_ privateTimestamp $ writeKey opts "timestamp"
    forM_ privateSnapshot  $ writeKey opts "snapshot"
    forM_ privateMirrors   $ writeKey opts "mirrors"

readKeysAt :: AbsolutePath -> IO [Some Key]
readKeysAt dir = catMaybes <$> do
    contents <- getDirectoryContents dir
    forM (filter (not . skip) contents) $ \file -> do
      let path = dir </> fragment file
      mKey <- readCanonical KeyEnv.empty path
      case mKey of
        Left _err -> do logWarn $ "Skipping unrecognized " ++ show path
                        return Nothing
        Right key -> return $ Just key
  where
    skip :: Fragment -> Bool
    skip "."  = True
    skip ".." = True
    skip _    = False

writeKey :: GlobalOpts -> Fragment -> Some Key -> IO ()
writeKey GlobalOpts{..} prefix key = do
    logInfo $ "Writing " ++ show path
    createDirectoryIfMissing True (takeDirectory path)
    writeCanonical path key
  where
    kId  = keyIdString (someKeyId key)
    path = globalKeys </> fragment prefix </> fragment kId <.> "private"

{-------------------------------------------------------------------------------
  Bootstrapping / updating

  TODO: Some of this functionality should be moved to
  @Hackage.Security.Server.*@ (to be shared by both, say, Hackage, and
  secure-local),  but I'm not sure precisely in what form yet.
-------------------------------------------------------------------------------}

bootstrapOrUpdate :: GlobalOpts -> Bool -> IO ()
bootstrapOrUpdate opts@GlobalOpts{..} isBootstrap = do
    keys <- readKeys opts
    now  <- getCurrentTime

    -- We overwrite files during bootstrap process, but update them only
    -- if necessary during an update. Note that we _only_ write the updated
    -- files to the tarball, so the user deletes the tarball and then calls
    -- update (rather than bootstrap) the tarball will be missing files.
    let whenWrite = if isBootstrap
                      then WriteAlways
                      else WriteIfNecessary

    newBootstrapped <-
      if not isBootstrap
        then return []
        else do
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
          void $ updateFile whenWrite
                            globalRepo
                            (fragment "root.json")
                            (withSignatures (privateRoot keys))
                            root

          -- Create mirrors
          let mkMirror uri = Mirror uri MirrorFull
          let mirrors = Mirrors {
                  mirrorsVersion = versionInitial
                , mirrorsExpires = expiresInDays now (10 * 365)
                , mirrorsMirrors = map mkMirror globalMirrors
                }
          void $ updateFile whenWrite
                            globalRepo
                            (fragment "mirrors.json")
                            (withSignatures (privateMirrors keys))
                            mirrors

          -- Create global package metadata
          --
          -- NOTE: Until we introduce author signing, this file is entirely static
          -- (and in fact ignored)
          let globalTargets = Targets {
                  targetsVersion     = versionInitial
                , targetsExpires     = expiresNever
                , targetsTargets     = FileMap.empty
                , targetsDelegations = Just $ Delegations {
                      delegationsKeys  = KeyEnv.empty
                    , delegationsRoles = [
                          DelegationSpec {
                              delegationSpecKeys      = []
                            , delegationSpecThreshold = KeyThreshold 0
                            , delegation = $(qqd "*/*/*" "*/*/targets.json")
                            }
                        ]
                    }
                }
          newGlobalTargets <- updateFile whenWrite
                                         globalRepo
                                         (fragment "targets.json")
                                         (withSignatures (privateTarget keys))
                                         globalTargets

          return [newGlobalTargets]

    -- Create targets.json for each package version
    pkgs <- findPackages opts
    newPackageMetadata <- forM pkgs $ createPackageMetadata opts whenWrite

    -- New files to be added to the index
    let newFiles :: [UnrootedPath]
        newFiles = concat [
            catMaybes newBootstrapped
          , concat newPackageMetadata
          ]

    -- Recreate index tarball
    -- TODO: This currently does not allow for .cabal file revisions
    -- (I don't know if this is relevant at all for local repos)
    -- NOTE: This cannot contain snapshot.json (because snapshot has the
    -- hash of the index) or timestamp.json (because that in turn has the
    -- hash of the snapshot).
    extraFiles <- findExtraIndexFiles opts
    -- TODO: Currently this means that we add the extra files a-new to the index
    -- on every iteration
    let addToIndex = newFiles ++ extraFiles
    case whenWrite of
      WriteAlways -> do
        -- If we are recreating all files, also recreate the index
        removeFile pathIndexTar
        logInfo $ "Writing " ++ show pathIndexTar
      WriteIfNecessary -> do
        logInfo $ "Appending to " ++ show pathIndexTar
    Index.append
      pathIndexTar
      globalRepo
      addToIndex
    writeLazyByteString pathIndexTarGz =<<
      GZip.compress <$> readLazyByteString pathIndexTar

    -- Create snapshot
    -- TODO: If we are updating we should be incrementing the version, not
    -- keeping it the same
    rootInfo    <- computeFileInfo pathRoot
    mirrorsInfo <- computeFileInfo pathMirrors
    tarInfo     <- computeFileInfo pathIndexTar
    tarGzInfo   <- computeFileInfo pathIndexTarGz
    let snapshot = Snapshot {
            snapshotVersion     = versionInitial
          , snapshotExpires     = expiresInDays now 3
          , snapshotInfoRoot    = rootInfo
          , snapshotInfoMirrors = mirrorsInfo
          , snapshotInfoTar     = Just tarInfo
          , snapshotInfoTarGz   = tarGzInfo
          }
    void $ updateFile whenWrite
                      globalRepo
                      (fragment "snapshot.json")
                      (withSignatures (privateSnapshot keys))
                      snapshot

    -- Finally, create the timestamp
    snapshotInfo <- computeFileInfo pathSnapshot
    let timestamp = Timestamp {
            timestampVersion      = versionInitial
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = snapshotInfo
          }
    void $ updateFile whenWrite
                      globalRepo
                      (fragment "timestamp.json")
                      (withSignatures (privateTimestamp keys))
                      timestamp
  where
    pathRoot       = globalRepo </> fragment "root.json"
    pathMirrors    = globalRepo </> fragment "mirrors.json"
    pathSnapshot   = globalRepo </> fragment "snapshot.json"
    pathIndexTar   = globalRepo </> fragment "00-index.tar"
    pathIndexTarGz = globalRepo </> fragment "00-index.tar.gz"

-- | Create package metadata
--
-- If we find that the package metadata has changed, we return the path of the
-- new @target.json@ as well as the path of the @.cabal@ file so that we know
-- to include it in the index. If nothing changed, we return the empty list.
createPackageMetadata :: GlobalOpts -> WhenWrite -> PackageIdentifier -> IO [UnrootedPath]
createPackageMetadata GlobalOpts{..} whenWrite pkgId = do
    fileMapEntries <- computeFileMapEntries
    checkEntries fileMapEntries
    let targets = Targets {
            targetsVersion     = versionInitial
          , targetsExpires     = expiresNever
          , targetsTargets     = FileMap.fromList fileMapEntries
          , targetsDelegations = Nothing
          }
    -- Currently we "sign" with no keys
    mUpdated <- updateFile whenWrite
                           globalRepo
                           (pathPkgMetadata pkgId)
                           (withSignatures [])
                           targets
    case mUpdated of
      Nothing      -> return []
      Just updated -> return [updated, pathPkgCabal pkgId]
  where
    computeFileMapEntries :: IO [(UnrootedPath, FileInfo)]
    computeFileMapEntries = catMaybes <$> do
      contents <- getDirectoryContents fullPkgPath
      forM (filter (not . skip) contents) $ \file -> do
        let path = fullPkgPath </> fragment file
        isDir <- doesDirectoryExist path
        if isDir
          then do
            logWarn $ "Skipping unrecognized " ++ show path
            return Nothing
          else do
            let (_, ext) = splitExtension path
            -- TODO: Not sure how (or if) cabal revisions are stored
            case ext of
              ".gz"      -> Just <$> computeFileMapEntry file
              ".cabal"   -> Just <$> computeFileMapEntry file
              _otherwise -> do logWarn $ "Skipping unrecognized " ++ show path
                               return Nothing

    checkEntries :: [(UnrootedPath, a)] -> IO ()
    checkEntries entries = do
        unless (has ".gz") $
          logWarn $ "No .gz file for package " ++ display pkgId
        unless (has ".cabal") $
          logWarn $ "No .cabal file for package " ++ display pkgId
      where
        has :: String -> Bool
        has ext = not . null $ filter (matchesExt ext . fst) entries

        matchesExt :: String -> UnrootedPath -> Bool
        matchesExt ext fp = let (_, ext') = splitExtension fp in ext == ext'

    computeFileMapEntry :: Fragment -> IO (UnrootedPath, FileInfo)
    computeFileMapEntry file = do
      info <- computeFileInfo (fullPkgPath </> fragment file)
      return (fragment file, info)

    fullPkgPath :: AbsolutePath
    fullPkgPath = globalRepo </> pathPkg pkgId

    skip :: Fragment -> Bool
    skip "."            = True
    skip ".."           = True
    skip "targets.json" = True
    skip _              = False

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Find all packages in a local repository
--
-- We don't rely on the index because we might have to _create_ the index.
findPackages :: GlobalOpts -> IO [PackageIdentifier]
findPackages GlobalOpts{..} = do
    contents <- getDirectoryContents globalRepo
    pkgs <- forM (filter (not . skipPkg) contents) $ \pkg -> do
      let path = globalRepo </> fragment pkg
      isDir <- doesDirectoryExist path
      if isDir
        then
          findVersions pkg
        else do
          logWarn $ "Skipping unrecognized file " ++ show path
          return []
    return $ concat pkgs
  where
    findVersions :: Fragment -> IO [PackageIdentifier]
    findVersions pkg = catMaybes <$> do
        contents <- getDirectoryContents (globalRepo </> fragment pkg)
        forM (filter (not . skipVersion) contents) $ \version -> do
          let path = globalRepo </> fragment pkg </> fragment version
          isDir <- doesDirectoryExist path
          if isDir
             then
               case simpleParse (pkg ++ "-" ++ version) of
                 Just pkgId -> return $ Just pkgId
                 Nothing    -> do logWarn $ "Skipping unrecognized " ++ show path
                                  return Nothing
             else do
               logWarn $ "Skipping unrecognized " ++ show path
               return Nothing

    skipPkg :: Fragment -> Bool
    skipPkg "."                       = True
    skipPkg ".."                      = True
    skipPkg "00-index.tar"            = True
    skipPkg "00-index.tar.gz"         = True
    skipPkg "preferred-versions"      = True
    skipPkg "targets.json"            = True
    skipPkg "root.json"               = True
    skipPkg "snapshot.json"           = True
    skipPkg "timestamp.json"          = True
    skipPkg "timestamp-snapshot.json" = True
    skipPkg "mirrors.json"            = True
    skipPkg _                         = False

    skipVersion :: Fragment -> Bool
    skipVersion "."  = True
    skipVersion ".." = True
    skipVersion _    = False

-- | Find additional files that should be added to the index
findExtraIndexFiles :: GlobalOpts -> IO [UnrootedPath]
findExtraIndexFiles GlobalOpts{..} = catMaybes <$> do
    forM extraIndexFiles $ \file -> do
      let path = globalRepo </> fragment file
      isFile <- doesFileExist path
      if isFile then return $ Just (fragment file)
                else return Nothing
  where
    extraIndexFiles :: [Fragment]
    extraIndexFiles = [
        "preferred-versions"
      ]

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

pathPkg :: PackageIdentifier -> UnrootedPath
pathPkg pkgId =  fragment (display (packageName    pkgId))
             </> fragment (display (packageVersion pkgId))

pathPkgCabal :: PackageIdentifier -> UnrootedPath
pathPkgCabal pkgId =  pathPkg pkgId
                  </> fragment (display (packageName pkgId))
                  <.> "cabal"

pathPkgMetadata :: PackageIdentifier -> UnrootedPath
pathPkgMetadata pkgId =  pathPkg pkgId
                     </> fragment "targets.json"

{-------------------------------------------------------------------------------
  Logging

  TODO: Replace this with a proper logging package
-------------------------------------------------------------------------------}

logInfo :: String -> IO ()
logInfo str = putStrLn $ "Info: " ++ str

logWarn :: String -> IO ()
logWarn str = putStrLn $ "Warning: " ++ str

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

data WhenWrite = WriteIfNecessary | WriteAlways

-- | Write canonical JSON
--
-- We write the file to a temporary location and compare file info with the file
-- that was already in the target location (if any). If it's the same (modulo
-- version number) we don't overwrite it and return Nothing; otherwise we
-- increment the version number, write the file, and return the path to the file
-- that we wrote (not including the baseDir).
--
-- TODO: This currently uses withSystemTempFile, which means that 'renameFile'
-- might not work. Instead we should (here and elsewhere) have a temporary
-- directory on the same file system. A worry for later.
updateFile :: (ToJSON (Signed a), HasHeader a)
           => WhenWrite        -- ^ When should we overwrite the existing file?
           -> AbsolutePath     -- ^ Base directory
           -> UnrootedPath     -- ^ Path relative to base directory
           -> (a -> Signed a)  -- ^ Signing function
           -> a                -- ^ Unsigned object
           -> IO (Maybe UnrootedPath)
updateFile whenWrite baseDir file signPayload a = do
    mOldHeader :: Maybe (Either DeserializationError (IgnoreSigned Header)) <-
      handleDoesNotExist $ readNoKeys fp

    case (whenWrite, mOldHeader) of
      (WriteAlways, _) -> do
        logInfo $ "Writing " ++ show file
        writeCanonical fp (signPayload a)
        return $ Just file
      (WriteIfNecessary, Nothing) -> do
        -- If there is no previous version of the file, or the old file is
        -- broken just create the new file
        logInfo $ "Creating " ++ show file
        writeCanonical fp (signPayload a)
        return $ Just file
      (WriteIfNecessary, Just (Left _err)) -> do
        -- If the old file is corrupted, warn and overwrite
        logWarn $ "Overwriting " ++ show file ++ " (old file corrupted)"
        writeCanonical fp (signPayload a)
        return $ Just file
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

        withSystemTempFile (takeFileName file) $ \tempPath h -> do
          -- Write new file, but using old file version
          BS.L.hPut h $ renderJSON (signPayload wOldVersion)
          hClose h

          -- Compare file hashes
          oldFileInfo <- computeFileInfo' fp
          newFileInfo <- computeFileInfo tempPath
          if oldFileInfo == Just newFileInfo
            then do
              logInfo $ "Unchanged " ++ show file
              return $ Nothing
            else do
              -- If changed, write file using incremented file version
              logInfo $ "Updating " ++ show file
              writeCanonical fp (signPayload wIncVersion)
              return $ Just file
  where
    fp = baseDir </> file

computeFileInfo' :: AbsolutePath -> IO (Maybe FileInfo)
computeFileInfo' fp =
    handle doesNotExist $ Just <$> computeFileInfo fp
  where
    doesNotExist e = if isDoesNotExistError e
                       then return Nothing
                       else throwIO e
