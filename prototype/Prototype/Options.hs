module Prototype.Options (
    Options(..)
  , Command(..)
  , getOptions
  ) where

import Data.Monoid
import Data.Version
import Options.Applicative

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Options = Options {
    optServer  :: FilePath
  , optClient  :: FilePath
  , optOffline :: FilePath
  , optCommand :: Command
  }
  deriving Show

data Command =
    -- | Bootstrap the server
    --
    -- Creates the initial root.json, root keys, etc.
    Bootstrap

    -- | Internal check: attempt to parse and then unparse a file
  | Roundtrip FilePath

    -- | Check for updates on the server
  | Check

    -- | Upload a new version for a package
  | Upload String Version
  deriving Show

{-------------------------------------------------------------------------------
  Parsers
-------------------------------------------------------------------------------}

parseOptions :: Parser Options
parseOptions = Options
  <$> (strOption $ mconcat [
          long "server"
        , metavar "DIR"
        , value "prototype-state/server"
        , showDefault
        , help "Server path"
        ])
  <*> (strOption $ mconcat [
          long "client"
        , metavar "DIR"
        , value "prototype-state/client"
        , showDefault
        , help "Path for client state"
        ])
  <*> (strOption $ mconcat [
          long "offline"
        , metavar "DIR"
        , value "prototype-state/offline"
        , showDefault
        , help "Path for \"offline\" files (keys, primarily)"
        ])
  <*> (subparser $ mconcat [
          command "bootstrap" $
            info (pure Bootstrap)
                 (progDesc "Bootstrap the server")
        , command "roundtrip" $
            info (Roundtrip <$> parseFilePath)
                 (progDesc "Roundtrip a JSON file")
        , command "check" $
            info (pure Check)
                 (progDesc "Check for updates")
        , command "upload" $
            info (Upload <$> argument str (metavar "PKG_NAME")
                         <*> argument auto (metavar "VERSION"))
                 (progDesc "Upload a (new version of) a package")
        ])

parseFilePath :: Parser FilePath
parseFilePath = argument str (metavar "PATH")

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

getOptions :: IO Options
getOptions = execParser opts
  where
    opts = info (helper <*> parseOptions) $ mconcat [
        fullDesc
      , progDesc "Client interface"
      , header "Secure Hackage Prototype"
      ]
