module Hackage.Security.Local.Options (
    GlobalOpts(..)
  , Command(..)
  , getOptions
  ) where

import Network.URI (URI, parseURI)
import Options.Applicative
import System.IO.Unsafe (unsafePerformIO)

import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Types
-------------------------------------------------------------------------------}

-- | Command line options
data GlobalOpts = GlobalOpts {
    -- | Root directory of the repository
    --
    -- We expect the repo to have the format
    --
    -- > foo/1.0/foo-1.0.tar.gz
    -- > foo/1.0/foo.cabal
    -- > foo/1.1/foo-1.1.tar.gz
    -- > foo/1.1/foo.cabal
    -- > foo/1.2/..
    -- > bar/..
    -- > baz/..
    -- > ..
    globalRepo :: AbsolutePath

    -- | Root directory of the keys
    --
    -- We expect this directory to have the format
    --
    -- root/<keyid1>.private
    -- root/<keyid2>.private
    -- root/..
    -- target/..
    -- snapshot/..
    -- timestamp/..
    --
    -- The @create-keys@ option can be used to create this directory.
  , globalKeys :: AbsolutePath

    -- | Mirrors (to add to @mirrors.json@)
  , globalMirrors :: [URI]

    -- | Command to execute
  , globalCommand :: Command
  }
  deriving Show

data Command =
    -- | Create keys
    CreateKeys

    -- | Create initial secure files
  | Bootstrap

    -- | Update a previously bootstrapped repo
  | Update
  deriving Show

{-------------------------------------------------------------------------------
  Parsers
-------------------------------------------------------------------------------}

getOptions :: IO GlobalOpts
getOptions = execParser opts
  where
    opts = info (helper <*> parseGlobalOptions) $ mconcat [
        fullDesc
      , header "Manage local Hackage repositories"
      ]

parseGlobalOptions :: Parser GlobalOpts
parseGlobalOptions = GlobalOpts
  <$> (option (str >>= readAbsolutePath) $ mconcat [
          long "repo"
        , metavar "PATH"
        , help "Path to local repository"
        ])
  <*> (option (str >>= readAbsolutePath) $ mconcat [
          long "keys"
        , metavar "PATH"
        , help "Path to key store"
        ])
  <*> (many . option (str >>= readURI) $ mconcat [
          long "mirror"
        , metavar "URI"
        , help "Mirror (to add to mirrors.json)"
        ])
  <*> (subparser $ mconcat [
          command "create-keys" (info (pure CreateKeys)
              (progDesc "Create keys"))
        , command "bootstrap" (info (pure Bootstrap)
            (progDesc "Bootstrap a local repository"))
        , command "update" (info (pure Update)
            (progDesc "Update a (previously bootstrapped) local repository"))
        ])

readURI :: String -> ReadM URI
readURI uriStr =
   case parseURI uriStr of
     Nothing  -> fail $ "Invalid URI " ++ show uriStr
     Just uri -> return uri

readAbsolutePath :: String -> ReadM AbsolutePath
readAbsolutePath filePath =
   case fromFilePath filePath of
     -- Sadly, cannot do I/O actions inside ReadM
     FileSystemPath path -> return $ unsafePerformIO $ makeAbsolute path
