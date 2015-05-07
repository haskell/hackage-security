module Hackage.Security.Client (
    Repository(..)
  , File(..)
  , checkForUpdates
  ) where

import Control.Exception
import Data.Time

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.TUF
import Hackage.Security.Verified
import qualified Hackage.Security.Key.Env as KeyEnv

data File =
    FileSnapshot
  | FileTimestamp
  | FileRoot

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Download a file from the server
    repGetRemote :: File -> IO FilePath

    -- | Get a cached file (if it exists)
  , repGetCached :: File -> IO (Maybe FilePath)

    -- | Get the (cached) root metadata
    --
    -- This must always succeed; how the initial root metadata is distributed
    -- to clients is outside the scope of this module.
  , repGetRoot :: IO FilePath
  }

-- | Generic logic for checking if there are updates
--
-- This implements the logic described in Section 5.1, "The client application",
-- of the TUF spec.
checkForUpdates :: Repository -> IO Bool
checkForUpdates Repository{..} = do
    -- TODO: We should make checking expiry dates optional
    now <- getCurrentTime

    -- We need the cached root information in order to resolve key IDs and
    -- verify signatures
    cachedRoot <- decode KeyEnv.empty =<< repGetRoot
    let keyEnv = rootKeys (signed cachedRoot)

    -- Get the old timestamp (if any)
    mOldTimestamp :: Maybe (Signed Timestamp)
                        <- repGetCached FileTimestamp
                       >>= decode' keyEnv

    -- Get the new timestamp
    newTimestamp :: Verified Timestamp
                    <- repGetRemote FileTimestamp
                   >>= decode keyEnv
                   >>= verifyRole'
                         (roleTimestamp (signed cachedRoot))
                         (fmap (_timestampVersion . signed) mOldTimestamp)
                         (Just now)

    return undefined

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

decode :: FromJSON ReadJSON a => KeyEnv -> FilePath -> IO a
decode keyEnv fpath = do
    result <- readCanonical keyEnv fpath
    case result of
      Left err -> throwIO err
      Right a  -> return a

decode' :: FromJSON ReadJSON a => KeyEnv -> Maybe FilePath -> IO (Maybe a)
decode' _      Nothing      = return Nothing
decode' keyEnv (Just fpath) = Just <$> decode keyEnv fpath

verifyRole' :: VerificationInfo a
            => RoleSpec           -- ^ Role specification to verify signatures
            -> Maybe FileVersion  -- ^ Previous file version (if any)
            -> Maybe UTCTime      -- ^ Time it is now to check expiry (if using)
            -> Signed a -> IO (Verified a)
verifyRole' role mPrev mNow signed =
    case verifyRole role mPrev mNow signed of
      Left err       -> throwIO err
      Right verified -> return verified
