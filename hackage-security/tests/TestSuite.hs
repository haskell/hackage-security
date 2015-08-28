module Main (main) where

-- stdlib
import Data.Time
import Test.Tasty
import Test.Tasty.HUnit
import System.IO.Temp (withSystemTempDirectory)
-- import Test.HUnit

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Util.Path
import Hackage.Security.Util.Checked

-- TestSuite
import TestSuite.InMemCache
import TestSuite.InMemRepo
import TestSuite.InMemRepository
import TestSuite.PrivateKeys

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
      ]

{-------------------------------------------------------------------------------
  In-memory tests

  These tests test the core TUF infrastructure, but any specific Repository
  implementation; instead, they use one specifically designed for testing
  (almost a Repository mock-up).
-------------------------------------------------------------------------------}

-- | Initial check for updates: empty cache
testInitialHasUpdates :: Assertion
testInitialHasUpdates = inMemTest $ \_inMemRepo repo -> do
    assertEqual "A" HasUpdates =<< checkForUpdates repo =<< checkExpiry

-- | Check that if we run updates again, with no changes on the server,
-- we get NoUpdates
testNoUpdates :: Assertion
testNoUpdates = inMemTest $ \_inMemRepo repo -> do
    assertEqual "A" HasUpdates =<< checkForUpdates repo =<< checkExpiry
    assertEqual "B" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

-- | Test that we have updates reported after the timestamp is resigned
testUpdatesAfterCron :: Assertion
testUpdatesAfterCron = inMemTest $ \inMemRepo repo -> do
    assertEqual "A" HasUpdates =<< checkForUpdates repo =<< checkExpiry
    assertEqual "B" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

    inMemCron inMemRepo =<< getCurrentTime

    assertEqual "C" HasUpdates =<< checkForUpdates repo =<< checkExpiry
    assertEqual "D" NoUpdates  =<< checkForUpdates repo =<< checkExpiry

inMemTest :: ( ( Throws SomeRemoteError
               , Throws VerificationError
               ) => InMemRepo -> Repository -> Assertion
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
      test inMemRepo $ newInMemRepository layout inMemRepo inMemCache
  where
    layout :: RepoLayout
    layout = hackageRepoLayout

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

checkExpiry :: IO (Maybe UTCTime)
checkExpiry = Just `fmap` getCurrentTime
