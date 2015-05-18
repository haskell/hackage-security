module Hackage.Security.Local.Options (
    GlobalOpts(..)
  , Command(..)
  , getOptions
  ) where

import Options.Applicative

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
    globalRepo :: FilePath

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
  , globalKeys :: FilePath

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
  <$> (strOption $ mconcat [
          long "repo"
        , metavar "PATH"
        , help "Path to local repository"
        ])
  <*> (strOption $ mconcat [
          long "keys"
        , metavar "PATH"
        , help "Path to key store"
        ])
  <*> (subparser $ mconcat [
          command "create-keys" (info (pure CreateKeys)
              (progDesc "Create keys"))
        , command "bootstrap" (info (pure Bootstrap)
            (progDesc "Bootstrap a local repository"))
        , command "update" (info (pure Update)
            (progDesc "Update a (previously bootstrapped) local repository"))
        ])
