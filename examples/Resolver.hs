{-# LANGUAGE UnicodeSyntax #-}

import Data.Foldable (forM_)
import Data.Maybe (listToMaybe)
import Data.List (isPrefixOf)
import Data.Char (isDigit)
import Data.Serialize
import Data.Textual (fromString)
import Network.DNS
import Control.Monad (join, void)
import System.Environment (getArgs)
import System.IO
import System.Posix.Socket
import System.Posix.Socket.Inet

main ∷ IO ()
main = do
  mName ← fmap (join . fmap fromString . listToMaybe) getArgs
  forM_ mName $ \name → do
    putStrLn $ "Resolving " ++ show name
    mAddr ← 
      fmap (join
            . fmap (fromString . dropWhile (not . isDigit))
            . listToMaybe
            . filter ("nameserver " `isPrefixOf`)
            . lines) $
        openFile "/etc/resolv.conf" ReadMode >>= hGetContents
    forM_ mAddr $ \addr → do
      putStrLn $ "Resolver address: " ++ show addr
      sk ← socket AF_INET datagramSockType defaultSockProto
      let req = DnsReq { dnsReqId       = 123
                       , dnsReqTruncd   = False
                       , dnsReqRec      = True
                       , dnsReqQuestion = DnsQuestion
                           { dnsQName = name
                           , dnsQType = StdDnsType AddrDnsType } }
          reqBs = encode req
      putStrLn $ "Raw request: " ++ show reqBs
      void $ sendTo sk reqBs (InetAddr addr 53)
      (_, respBs) ← recvFrom sk 1024
      putStrLn $ "Raw response: " ++ show respBs
      case decode respBs of
        Left err   → putStrLn $ "Parsing failed: " ++ err
        Right resp → putStrLn $ "Parsed response: " ++ show (resp ∷ DnsResp)

