{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}

import Data.Foldable (forM_)
import Data.Maybe (listToMaybe)
import Data.List (isPrefixOf)
import Data.Char (isDigit)
import Data.Serializer (toByteString)
import Data.Deserializer (Deserialized(..), deserializeByteString)
import Data.Textual (fromString)
import Network.IP.Addr (InetAddr(..))
import Network.DNS
import Control.Monad (join, void)
import System.Environment (getArgs)
import System.IO

#ifdef OS_Win32
import System.Exit (exitFailure)

main ∷ IO ()
main = do
  putStrLn "This example works only on POSIX systems"
  exitFailure
#else
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
      sk ← socket AF_INET SOCK_DGRAM defaultSockProto
      let req = DnsReq { dnsReqId       = 123
                       , dnsReqTruncd   = False
                       , dnsReqRec      = True
                       , dnsReqQuestion = DnsQuestion
                           { dnsQName = name
                           , dnsQType = StdDnsType AddrDnsType } }
          reqBs = toByteString req
      putStrLn $ "Raw request: " ++ show reqBs
      void $ sendTo sk reqBs (InetAddr addr 53)
      (_, respBs) ← recvFrom sk 1024
      putStrLn $ "Raw response: " ++ show respBs
      case deserializeByteString respBs of
        Malformed _ err →
          putStrLn $ "Parsing failed: " ++ err
        Deserialized resp →
          putStrLn $ "Parsed response: " ++ show (resp ∷ DnsResp)
#endif

