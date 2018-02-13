{-# LANGUAGE ViewPatterns #-}

import Control.Monad
import Control.Concurrent
import Control.Concurrent.Async
import System.Environment
import System.Exit
import System.Process
import System.IO

import System.FileLock

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  args <- getArgs
  case args of
    ["shared", read -> duration]
      -> holdLock "shared" Shared duration
    ["exclusive", read -> duration]
      -> holdLock "exclusive" Exclusive duration
    ["try"]
      -> tryTakingLock
    ["tryshared", read -> duration]
      -> tryHoldLock "shared" Shared duration
    ["tryexclusive", read -> duration]
      -> tryHoldLock "exclusive" Exclusive duration
    _ -> do
      withFile "lock.log" WriteMode $ \h ->
        void $ mapConcurrently id
          [ callSelf h ["shared", "300"]
          , callSelf h ["shared", "200"]
          , msleep 10 >> callSelf h ["exclusive", "500"]
          , msleep 20 >> callSelf h ["try"]
          , msleep 50 >> callSelf h ["shared", "500"]
          , msleep 700 >> callSelf h ["shared", "10"]
          , msleep 1500 >> callSelf h ["try"]
          ]
      msleep 2000
      log <- readFile "lock.log"
      expected <- readFile "tests/lock.log.expected"
      when (log /= expected) $ do
        putStrLn "log mismatch!"
        exitFailure

callSelf :: Handle -> [String] -> IO ()
callSelf out args = do
  self <- getExecutablePath
  (_hin, _hout, _herr, ph) <- createProcess_ "callSelf"
    (proc self args) { std_out = UseHandle out }
  ExitSuccess <- waitForProcess ph
  return ()

msleep :: Int -> IO ()
msleep = threadDelay . (*1000)

holdLock :: String -> SharedExclusive -> Int -> IO ()
holdLock ty sex duration = do
  withFileLock lockfile sex $ \_ -> do
    putStrLn $ "took " ++ desc
    msleep duration
  putStrLn $ "released " ++ desc
  where
    desc = ty ++ " lock"

tryTakingLock :: IO ()
tryTakingLock = do
  ml <- tryLockFile lockfile Exclusive
  case ml of
    Nothing -> putStrLn "lock not available"
    Just l -> do
      putStrLn "lock was available"
      unlockFile l

tryHoldLock :: String -> SharedExclusive -> Int -> IO ()
tryHoldLock ty sex duration = do
  res <- withTryFileLock lockfile sex $ \_ -> do
    putStrLn $ "took " ++ desc
    msleep duration
  case res of
    Nothing -> putStrLn "lock not available"
    Just _  -> putStrLn $ "released " ++ desc
  where
    desc = ty ++ " lock"

lockfile :: String
lockfile = "lock"
