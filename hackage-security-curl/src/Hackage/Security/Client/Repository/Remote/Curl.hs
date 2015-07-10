-- | Implementation of 'HttpClient' using external downloader
module Hackage.Security.Client.Repository.Remote.Curl (
    withClient
  ) where

import Control.Monad
import Network.URI
import System.Process
import System.IO
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Lazy.Internal as BS.L

import Hackage.Security.Client.Repository.Remote

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

-- | HttpClient using external 'curl' executable
--
-- This is currently just a proof of concept. With a bit of luck we'll be
-- able to reuse most of https://github.com/haskell/cabal/pull/2613 for a
-- more serious implementation.
--
-- TODO: Deal with _proxy
withClient :: ProxyConfig String -> (String -> IO ()) -> (HttpClient -> IO a) -> IO a
withClient _proxy _logger callback = do
    caps <- newServerCapabilities
    callback HttpClient {
      httpClientGet          = get
    , httpClientGetRange     = undefined -- TODO: support range requests
    , httpClientCapabilities = caps
    , httpWrapCustomEx       = id
    }

{-------------------------------------------------------------------------------
  Implementation of the individual methods
-------------------------------------------------------------------------------}

-- TODO: Interpret the HTTP options
get :: [HttpOption] -> URI -> (BodyReader -> IO a) -> IO a
get _httpOpts uri callback = do
    (Nothing, Just hOut, Nothing, hProc) <- createProcess curl
    callback (bodyReader hProc hOut)
  where
    curl :: CreateProcess
    curl = (proc "curl" [show uri]) { std_out = CreatePipe }

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Construct a body reader for a process
--
-- TODO: We should also deal with stderr
bodyReader :: ProcessHandle -> Handle -> BodyReader
bodyReader hProc hOut = do
    chunk <- BS.hGetSome hOut BS.L.smallChunkSize
    when (BS.null chunk) $ do
      _exitCode <- waitForProcess hProc
      -- TODO: Check for successful termination
      return ()
    return chunk
