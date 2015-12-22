{-# LANGUAGE CPP #-}
module ExampleClient.Options (
    GlobalOpts(..)
  , Command(..)
  , NewOnly
  , getOptions
    -- * Re-exports
  , URI
  ) where

import Data.List (isPrefixOf)
import Network.URI (URI, parseURI)
import Options.Applicative
import System.IO.Unsafe (unsafePerformIO)

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data GlobalOpts = GlobalOpts {
    -- | Path to the repository (local or remote)
    globalRepo :: Either (Path Absolute) URI

    -- | Directory to store the client cache
  , globalCache :: Path Absolute

    -- | HTTP client to use
  , globalHttpClient :: String

    -- | Trusted root key (used for bootstrapping)
  , globalRootKeys :: [KeyId]

    -- | Should we check expiry times?
  , globalCheckExpiry :: Bool

    -- | Should we disable content compression? (For the security paranoid)
  , globalDisallowCompression :: Bool

    -- | Command to execute
  , globalCommand :: Command
  }

data Command =
    -- | Get initial root info
    Bootstrap KeyThreshold

    -- | Check for updates on the server
  | Check

    -- | Download a specific package
  | Get PackageIdentifier

    -- | Enumerate the entries in the index
  | EnumIndex NewOnly
  deriving Show

type NewOnly = Bool

{-------------------------------------------------------------------------------
  Parsers
-------------------------------------------------------------------------------}

getOptions :: IO GlobalOpts
getOptions = execParser opts
  where
    opts = info (helper <*> parseGlobalOptions) $ mconcat [
        fullDesc
      , header "Example Hackage client"
      ]

parseBootstrap :: Parser Command
parseBootstrap = Bootstrap <$> argument readKeyThreshold (metavar "THRESHOLD")

parseCheck :: Parser Command
parseCheck = pure Check

parseGet :: Parser Command
parseGet = Get <$> argument readPackageIdentifier (metavar "PKG")

parseEnumIndex :: Parser Command
parseEnumIndex = EnumIndex
  <$> (switch $ mconcat [
      long "new-only"
    , help "Only enumerate entries since last call to enum-index"
    ])

parseGlobalOptions :: Parser GlobalOpts
parseGlobalOptions = GlobalOpts
  <$> (option (str >>= readRepo) $ mconcat [
          long "repo"
        , metavar "URL"
        , help "Location of the repository"
        ])
  <*> (option (str >>= readAbsolutePath) $ mconcat [
          long "cache"
        , metavar "PATH"
        , help "Path to client cache"
        ])
  <*> (strOption $ mconcat [
         long "http-client"
       , metavar "CLIENT"
       , value "HTTP"
       , showDefault
#ifdef MIN_VERSION_hackage_security_http_client
       , help "HTTP client to use (currently supported: HTTP, http-conduit, curl)"
#else
       , help "HTTP client to use (currently supported: HTTP, curl)"
#endif
       ])
  <*> (many . option readKeyId $ mconcat [
         long "root-key"
       , metavar "KEYID"
       , help "Root key (used for bootstrapping; can be used multiple times)"
       ])
  <*> (switch $ mconcat [
         long "ignore-expiry"
       , help "Don't check expiry dates (should only be used in exceptional circumstances)"
       ])
  <*> (switch $ mconcat [
         long "disallow-content-compression"
       , help "Disallow HTTP content compression (for the security paranoid)"
       ])
  <*> (subparser $ mconcat [
          command "bootstrap" $ info (helper <*> parseBootstrap) $
            progDesc "Get the initial root information. If using a key threshold larger than 0, you will need to use the --root-key option to specify one or more trusted root keys."
        , command "check" $ info (helper <*> parseCheck) $
            progDesc "Check for updates"
        , command "get" $ info (helper <*> parseGet) $
            progDesc "Download a package"
        , command "enum-index" $ info (helper <*> parseEnumIndex) $
            progDesc "Enumerate the index"
        ])

readKeyId :: ReadM KeyId
readKeyId = KeyId <$> str

readKeyThreshold :: ReadM KeyThreshold
readKeyThreshold = KeyThreshold <$> auto

readPackageIdentifier :: ReadM PackageIdentifier
readPackageIdentifier = do
    raw <- str
    case simpleParse raw of
      Just pkgId -> return pkgId
      Nothing    -> fail $ "Invalid package ID " ++ show raw

-- Sadly, cannot do I/O actions inside ReadM
readAbsolutePath :: String -> ReadM (Path Absolute)
readAbsolutePath = return . unsafePerformIO . makeAbsolute . fromFilePath

readRepo :: String -> ReadM (Either (Path Absolute) URI)
readRepo filePath =
    if "http://" `isPrefixOf` filePath
      then Right <$> readURI filePath
      else Left <$> readAbsolutePath filePath

readURI :: String -> ReadM URI
readURI uriStr =
   case parseURI uriStr of
     Nothing  -> fail $ "Invalid URI " ++ show uriStr
     Just uri -> return uri
