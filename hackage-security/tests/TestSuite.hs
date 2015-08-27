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
      ]

{-------------------------------------------------------------------------------
  In-memory tests

  These tests test the core TUF infrastructure, but any specific Repository
  implementation; instead, they use one specifically designed for testing
  (almost a Repository mock-up).
-------------------------------------------------------------------------------}

-- | Initial check for updates: empty cache
testInitialHasUpdates :: Assertion
testInitialHasUpdates = inMemTest $ \repo -> do
    assertEqual "" HasUpdates =<< checkForUpdates repo CheckExpiry

-- | Check that if we run updates again, with no changes on the server,
-- we get NoUpdates
testNoUpdates :: Assertion
testNoUpdates = inMemTest $ \repo -> do
    assertEqual "" HasUpdates =<< checkForUpdates repo CheckExpiry
    assertEqual "" NoUpdates  =<< checkForUpdates repo CheckExpiry

inMemTest :: ( ( Throws SomeRemoteError
               , Throws VerificationError
               ) => Repository -> Assertion
             )
          -> Assertion
inMemTest test = uncheckClientErrors $ do
    now  <- getCurrentTime
    keys <- createPrivateKeys
    let root = initRoot now layout keys
    withSystemTempDirectory "hackage-security-test" $ \tempDir' -> do
      tempDir <- makeAbsolute $ fromFilePath tempDir'
      repo    <- newInMemRepo  tempDir layout root now keys
      cache   <- newInMemCache tempDir layout root
      test $ newInMemRepository layout repo cache
  where
    layout :: RepoLayout
    layout = hackageRepoLayout
