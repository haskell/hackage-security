module Main (main) where

-- stdlib
import Data.Time
import Test.Tasty
import Test.Tasty.HUnit
import System.IO.Temp (withSystemTempDirectory)

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.JSON (DeserializationError(..))
import Hackage.Security.Util.Path
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Pretty

-- TestSuite
import TestSuite.InMemCache
import TestSuite.InMemRepo
import TestSuite.InMemRepository
import TestSuite.PrivateKeys
import TestSuite.Util.StrictMVar

{-------------------------------------------------------------------------------
  TestSuite driver
-------------------------------------------------------------------------------}

main :: IO ()
main = defaultMain (testGroup "InMem" tests)
  where
    tests :: [TestTree]
    tests = [
        testCase "testInitialHasForUpdates" testInitialHasUpdates
      , testCase "testNoUpdates"            testNoUpdates
      , testCase "testUpdatesAfterCron"     testUpdatesAfterCron
      , testCase "testKeyRollover"          testKeyRollover
      ]

{-------------------------------------------------------------------------------
  In-memory tests

  These tests test the core TUF infrastructure, but any specific Repository
  implementation; instead, they use one specifically designed for testing
  (almost a Repository mock-up).
-------------------------------------------------------------------------------}

-- | Initial check for updates: empty cache
testInitialHasUpdates :: Assertion
testInitialHasUpdates = inMemTest $ \_inMemRepo logMsgs repo -> do
    withAssertLog "A" logMsgs [] $
      assertEqual "A.1" HasUpdates =<< checkForUpdates repo =<< checkExpiry

-- | Check that if we run updates again, with no changes on the server,
-- we get NoUpdates
testNoUpdates :: Assertion
testNoUpdates = inMemTest $ \_inMemRepo logMsgs repo -> do
    withAssertLog "A" logMsgs [] $ do
      assertEqual "A.1" HasUpdates =<< checkForUpdates repo =<< checkExpiry
      assertEqual "A.2" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

-- | Test that we have updates reported after the timestamp is resigned
testUpdatesAfterCron :: Assertion
testUpdatesAfterCron = inMemTest $ \inMemRepo logMsgs repo -> do
    withAssertLog "A" logMsgs [] $ do
      assertEqual "A" HasUpdates =<< checkForUpdates repo =<< checkExpiry
      assertEqual "B" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

      inMemRepoCron inMemRepo =<< getCurrentTime

      assertEqual "C" HasUpdates =<< checkForUpdates repo =<< checkExpiry
      assertEqual "D" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

-- | Test what happens when the timestamp/snapshot keys rollover
testKeyRollover :: Assertion
testKeyRollover = inMemTest $ \inMemRepo logMsgs repo -> do
    withAssertLog "A" logMsgs [] $ do
      assertEqual "A.1" HasUpdates =<< checkForUpdates repo =<< checkExpiry
      assertEqual "A.2" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

    inMemRepoKeyRollover inMemRepo =<< getCurrentTime

    withAssertLog "B" logMsgs [unknownKeyError timestampPath] $ do
      assertEqual "D" HasUpdates =<< checkForUpdates repo =<< checkExpiry

    withAssertLog "C" logMsgs [] $ do
      assertEqual "H" NoUpdates =<< checkForUpdates repo =<< checkExpiry
  where
    timestampPath = repoLayoutTimestamp hackageRepoLayout

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

unknownKeyError :: RepoPath -> LogMessage -> Bool
unknownKeyError repoPath msg =
    case msg of
      LogVerificationError
        (VerificationErrorDeserialization
           (TargetPathRepo repoPath')
           (DeserializationErrorUnknownKey _keyId))
        -> repoPath == repoPath'
      _otherwise ->
        False

-- | Check the contents of the log
assertLog :: String -> [LogMessage -> Bool] -> [LogMessage] -> Assertion
assertLog label = go
  where
    go :: [LogMessage -> Bool] -> [LogMessage] -> Assertion
    go []     []     = return ()
    go []     (a:_)  = unexpected a
    go (_:_)  []     = assertFailure $ label ++ ": expected log message"
    go (e:es) (a:as) = if e a then go es as else unexpected a

    unexpected :: LogMessage -> Assertion
    unexpected msg = assertFailure $ label ++ ": "
                                  ++ "unexpected log message "
                                  ++ show (pretty msg)

-- | Run the actions and check its log messages
withAssertLog :: String
              -> MVar [LogMessage]
              -> [LogMessage -> Bool]
              -> Assertion -> Assertion
withAssertLog label mv expected action = do
    oldMsgs <- modifyMVar mv $ \old -> return ([], old)
    action
    newMsgs <- modifyMVar mv $ \new -> return (oldMsgs, new)
    assertLog label expected newMsgs

-- | Unit test using the in-memory repository/cache
inMemTest :: ( ( Throws SomeRemoteError
               , Throws VerificationError
               ) => InMemRepo -> MVar [LogMessage] -> Repository -> Assertion
             )
          -> Assertion
inMemTest test = uncheckClientErrors $ do
    now  <- getCurrentTime
    keys <- createPrivateKeys
    let root = initRoot now layout keys
    withSystemTempDirectory "hackage-security-test" $ \tempDir' -> do
      tempDir    <- makeAbsolute $ fromFilePath tempDir'
      inMemRepo  <- newInMemRepo  tempDir layout root now keys
      inMemCache <- newInMemCache tempDir layout root
      logMsgs    <- newMVar []
      let logger msg = modifyMVar_ logMsgs $ return . (msg:)
          repository = newInMemRepository layout inMemRepo inMemCache logger
      test inMemRepo logMsgs repository
  where
    layout :: RepoLayout
    layout = hackageRepoLayout

-- | Return @Just@ the current time
checkExpiry :: IO (Maybe UTCTime)
checkExpiry = Just `fmap` getCurrentTime
