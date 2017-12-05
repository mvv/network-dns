{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module provides Domain Name System data structures and
--   (de)serialization routines.
module Network.DNS
  ( HostName
  , aHostName
  , hostName
  , hostNameLabels
  , arpaHostName
  , HostAddr(..)
  , Host4Addr
  , Host6Addr
  , aHostAddr
  , aHostAddrOf
  , aHost4Addr
  , aHost6Addr
  , aHostAddrIP
  , DnsId
  , DnsType(..)
  , dnsTypeCode
  , DnsData(..)
  , DnsRecord(..)
  , DnsQType(..)
  , dnsQTypeCode
  , DnsQuestion(..)
  , DnsReq(..)
  , DnsError(..)
  , DnsResp(..)
  ) where

import Data.Typeable (Typeable)
#if !MIN_VERSION_base(4,7,0)
import Data.Typeable (Typeable1)
#endif
import Data.Proxy (Proxy(..))
import Data.Foldable (forM_)
import Data.Hashable
import Data.Word
import Data.Bits
import Data.Char (chr, ord)
import Data.Map (Map)
import qualified Data.Map as Map
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Builder as BB
import qualified Data.Binary.Get as B
import Data.Serializer (Serializer, Serializable, SizedSerializable)
import qualified Data.Serializer as S
import Data.Deserializer (Deserializer, Deserializable)
import qualified Data.Deserializer as D
import Text.Parser.Combinators as P
import Text.Parser.Char as P
import Text.Printer ((<>))
import qualified Text.Printer as T
import Data.Textual (Printable, toAscii, toUtf8, Textual)
import qualified Data.Textual as T
import qualified Text.Ascii as A
import Text.Printf
import qualified Text.Read as TR
import Network.IP.Addr
import Control.Applicative ((<$>), Applicative(..), (<|>))
import Control.Monad (void, unless, ap, foldM)

-- | Host name.
newtype HostName = HN { -- | Host name as a 'ByteString'.
                        hostName ∷ ByteString
                      }
                   deriving (Typeable, Eq, Ord, Hashable)

-- | 'HostName' proxy value.
aHostName ∷ Proxy HostName
aHostName = Proxy

instance Show HostName where
  showsPrec p (HN bs) = showParen (p > 10)
                      $ showString "fromJust "
                      . (showParen True $
                           showString "fromString "
                           . showsPrec 10 (BS8.unpack bs))

instance Read HostName where
  readPrec = TR.parens $ TR.prec 10 $ do
    TR.Ident "fromJust" ← TR.lexP
    TR.step $ TR.parens $ TR.prec 10 $ do
      TR.Ident "fromString" ← TR.lexP
      TR.String s ← TR.lexP
      Just n ← return $ T.fromString s
      return n

instance Printable HostName where
  print (HN bs) = T.ascii bs

{-# RULES "toAscii/HostName" toAscii = hostName #-}
{-# RULES "toUtf8/HostName"  toUtf8  = hostName #-}

instance Textual HostName where
  textual = go [] (0 ∷ Int) False [] (0 ∷ Int) <?> "host name"
    where alphaNumOrDashOrDot c = A.isAlphaNum c || c == '-' || c == '.'
          go !ls !ncs _ _ 0 =
            optional (satisfy A.isAlpha) >>= \case
              Just c  → if ncs == 255
                        then unexpected "Host name is too long"
                        else go ls (ncs + 1) False [A.ascii c] 1
              Nothing → unexpected "A letter expected"
          go !ls !ncs !dash !lcs !nlcs =
            optional (satisfy alphaNumOrDashOrDot) >>= \case
              Just '.' → if dash
                         then unexpected "Label ends with a dash"
                         else if ncs == 255
                              then unexpected "Host name is too long"
                              else go (reverse (A.ascii '.' : lcs) : ls)
                                      (ncs + 1) False [] 0
              Just c   → if nlcs == 63
                         then unexpected "Label is too long"
                         else if ncs == 255
                              then unexpected "Host name is too long"
                              else go ls (ncs + 1) (c == '-')
                                         (A.ascii c : lcs) (nlcs + 1)
              Nothing  → return $ HN $ BS.pack $ concat
                                $ reverse $ reverse lcs : ls

instance Printable (InetAddr HostName) where
  print (InetAddr n p) = T.print n <> T.char7 ':' <> T.print p

instance Textual (InetAddr HostName) where
  textual = InetAddr <$> T.textual <*> (P.char ':' *> T.textual)

-- | List the 'HostName' labels:
--
-- @
--   'hostNameLabels' ('Data.Maybe.fromJust' ('Data.Textual.fromString' /"www.google.com"/)) = [/"www"/, /"google"/, /"com"/]
-- @
hostNameLabels ∷ HostName → [ByteString]
hostNameLabels = BS.split (A.ascii '.') . hostName

-- | Host name for reverse DNS lookups.
--
-- @
--   'Text.Printer.toString' ('arpaHostName' ('IPv4' ('ip4FromOctets' /1/ /2/ /3/ /4/))) = /"4.3.2.1.in-addr.arpa"/
--   'Text.Printer.toString' ('arpaHostName' ('IPv6' ('ip6FromWords' /1/ /2/ /3/ /4/ /5/ /6/ /7/ /8/))) = /"8.0.0.0.7.0.0.0.6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.ip6.arpa"/
-- @
arpaHostName ∷ IP → HostName
arpaHostName (IPv4 a) =
    HN $ BS8.pack $ printf "%i.%i.%i.%i.in-addr.arpa" o4 o3 o2 o1
  where (o1, o2, o3, o4) = ip4ToOctets a
arpaHostName (IPv6 a) =
    HN $ BS8.pack $ digits (reverse $ ip6ToWordList a) ++ "ip6.arpa"
  where digits (w : ws) = [d4, '.', d3, '.', d2, '.', d1, '.'] ++ digits ws
          where d1 = toDigit $ w `shiftR` 12
                d2 = toDigit $ w `shiftR` 8 .&. 0xF
                d3 = toDigit $ w `shiftR` 4 .&. 0xF
                d4 = toDigit $ w .&. 0xF
                toDigit n | n < 10    = chr $ ord '0' + fromIntegral n
                          | otherwise = chr $ ord 'a' + fromIntegral n - 10
        digits [] = []

newtype Writer s α = Writer { runWriter ∷ (s → s) → (s → s, α) }

instance Functor (Writer s) where
  fmap f m = Writer $ \append →
               let (append', x) = runWriter m append
               in (append', f x)

instance Applicative (Writer s) where
  pure = return
  {-# INLINE pure #-}
  (<*>) = ap
  {-# INLINE (<*>) #-}

instance Monad (Writer s) where
  return x = Writer $ \append → (append, x)
  m >>= f = Writer $ \append →
              let (append', x) = runWriter m append
              in runWriter (f x) append'

newtype StateT k v μ α =
  StateT { runStateT ∷ Map k v → Maybe Word16 → μ (Map k v, Maybe Word16, α) }

type CompT s α   = StateT [ByteString] Word16 (Writer s) α
type DecompT μ α = StateT Word16 HostName μ α

compress ∷ Serializer s ⇒ Word16 → CompT s () → s
compress i m = append mempty
  where (append, _) = runWriter (runStateT m Map.empty $ Just i) id
{-# INLINE compress #-}

decompress ∷ Monad μ ⇒ Word16 → DecompT μ α → μ α
decompress i m = do
  (_, _, x) ← runStateT m Map.empty $ Just i
  return x
{-# INLINE decompress #-}

instance Monad μ ⇒ Functor (StateT k v μ) where
  fmap f m = StateT $ \ptrs offset → do
               (ptrs', offset', x) ← runStateT m ptrs offset
               return (ptrs', offset', f x)
  {-# INLINE fmap #-}

instance Monad μ ⇒ Applicative (StateT k v μ) where
  pure = return
  {-# INLINE pure #-}
  (<*>) = ap
  {-# INLINE (<*>) #-}

instance Monad μ ⇒ Monad (StateT k v μ) where
  return = lift . return
  {-# INLINE return #-}
  m >>= f = StateT $ \ptrs offset → do
              (ptrs', offset', x) ← runStateT m ptrs offset
              runStateT (f x) ptrs' offset'
  {-# INLINE (>>=) #-}
  fail msg = lift $ fail msg
  {-# INLINE fail #-}

lift ∷ Monad μ ⇒ μ α → StateT k v μ α
lift m = StateT $ \ptrs offset → do
           x ← m
           return (ptrs, offset, x)
{-# INLINE lift #-}

write ∷ Serializer s ⇒ s → CompT s ()
write s = lift $ Writer $ \append → ((append s <>), ())
{-# INLINE write #-}

getOffset ∷ Monad μ ⇒ StateT k v μ (Maybe Word16)
getOffset = StateT $ \ptrs offset → return (ptrs, offset, offset)
{-# INLINE getOffset #-}

addToOffset ∷ Word16 → Maybe Word16 → Maybe Word16
addToOffset n (Just i) | i' ← i + n, i' >= i && i' <= 0x3FFF = Just i'
addToOffset _ _ = Nothing
{-# INLINE addToOffset #-}

incOffset ∷ Monad μ ⇒ Word16 → StateT k v μ ()
incOffset n = StateT $ \ptrs offset →
  return (ptrs, addToOffset n offset, ())
{-# INLINE incOffset #-}

getEntries ∷ Monad μ ⇒ StateT k v μ (Map k v)
getEntries = StateT $ \ptrs offset → return (ptrs, offset, ptrs)
{-# INLINE getEntries #-}

getEntry ∷ (Ord k, Monad μ) ⇒ k → StateT k v μ (Maybe v)
getEntry key = StateT $ \ptrs offset → do
  return (ptrs, offset, Map.lookup key ptrs)
{-# INLINE getEntry #-}

putEntry ∷ (Ord k, Monad μ) ⇒ k → v → StateT k v μ ()
putEntry key value = StateT $ \ptrs offset → do
  return (Map.insert key value ptrs, offset, ())
{-# INLINE putEntry #-}

evalComp ∷ Serializer s ⇒ CompT BB.Builder () → CompT s BSL.ByteString
evalComp m = StateT $ \ptrs offset → do
  let (append, (ptrs', offset', _)) = runWriter (runStateT m ptrs offset) id
  return (ptrs', offset', BB.toLazyByteString (append mempty))
{-# INLINE evalComp #-}

evalDecomp ∷ Deserializer μ
           ⇒ Word16
           → DecompT D.BinaryDeserializer α
           → DecompT μ α
evalDecomp len m = StateT $ \ptrs offset → do
  buf ← BSL.fromStrict <$> D.take (fromIntegral len)
  let getM = D.binaryDeserializer $ runStateT m ptrs offset
  case B.runGetOrFail getM buf of
    Left (_, _, e) → unexpected e
    Right (_, _, (ptrs', _, x)) → return (ptrs', addToOffset len offset, x)

serializeHostName ∷ Serializer s ⇒ HostName → CompT s ()
serializeHostName = go . hostNameLabels
  where
    go [] = do
      write $ S.word8 0
      incOffset 1
    go labels@(label : labels') = do
      entry ← getEntry labels
      case entry of
        Nothing → do
          let ll = BS.length label
          offset ← getOffset
          write $  S.word8 (fromIntegral ll)
                <> S.byteString label
          incOffset $ 1 + fromIntegral ll
          forM_ offset $ putEntry labels
          go labels'
        Just ptr → do
          write $ S.word16B $ 0xC000 .|. ptr
          incOffset 2

guard ∷ Deserializer μ ⇒ String → Bool → μ ()
guard msg test = unless test $ unexpected msg
{-# INLINE guard #-}

deserializeHostName ∷ Deserializer μ ⇒ DecompT μ HostName
deserializeHostName = go []
  where
    folder suffix (label, offset) = do
        forM_ offset $ \i → putEntry i (HN suffix')
        return suffix'
      where suffix' = BS.append label $ BS.cons (A.ascii '.') suffix
    go labels = do
      offset ← getOffset
      w ← lift D.word8
      incOffset 1
      if w .&. 0xC0 == 0xC0
      then do
        w' ← lift D.word8
        incOffset 1
        let ptr = fromIntegral (w .&. 0x3F) `shiftL` 8 .|. fromIntegral w'
        entry ← getEntry ptr
        case entry of
          Nothing → do
            entries ← getEntries
            lift $ unexpected $  "Invalid pointer " ++ show ptr
                              ++ ": pointer map is "
                              ++ show (Map.elems entries)
          Just (HN suffix1) → HN <$> foldM folder suffix1 labels
      else
        if w == 0
        then do
          lift $ guard "Hostname with zero labels" $ not $ null labels
          let (lastLabel, lastOffset) : labels' = labels
          forM_ lastOffset $ \i → putEntry i (HN lastLabel)
          HN <$> foldM folder lastLabel labels'
        else do
          lift $ guard "Label is too long" $ w <= 63
          label ← lift $ D.take $ fromIntegral w
          incOffset $ fromIntegral w
          go ((BS.map A.toLower8 label, offset) : labels)

-- | Host address. Either a host name or an IP address.
data HostAddr a = HostName {-# UNPACK #-} !HostName
                | HostAddr !a
                deriving (Typeable, Show, Read, Eq, Ord)

type Host4Addr = HostAddr IP4
type Host6Addr = HostAddr IP6

-- | 'HostAddr' proxy value.
aHostAddr ∷ Proxy HostAddr
aHostAddr = Proxy

-- | 'HostAddr' /a/ proxy value.
aHostAddrOf ∷ Proxy a → Proxy (HostAddr a)
aHostAddrOf _ = Proxy

-- | 'Host4Addr' proxy value.
aHost4Addr ∷ Proxy Host4Addr
aHost4Addr = Proxy

-- | 'Host6Addr' proxy value.
aHost6Addr ∷ Proxy Host6Addr
aHost6Addr = Proxy

-- | 'HostAddr' 'IP' proxy value.
aHostAddrIP ∷ Proxy (HostAddr IP)
aHostAddrIP = Proxy

instance Printable a ⇒ Printable (HostAddr a) where
  print (HostName name) = T.print name
  print (HostAddr addr) = T.print addr

instance Textual a ⇒ Textual (HostAddr a) where
  textual  =  P.try (HostName <$> T.textual)
          <|> (HostAddr <$> T.textual)

instance Printable (InetAddr a) ⇒ Printable (InetAddr (HostAddr a)) where
  print (InetAddr (HostName n) p) = T.print $ InetAddr n p
  print (InetAddr (HostAddr a) p) = T.print $ InetAddr a p

instance Textual (InetAddr a) ⇒ Textual (InetAddr (HostAddr a)) where
  textual  =  P.try (InetAddr <$> (HostName <$> T.textual)
                              <*> (P.char ':' *> T.textual))
          <|> T.textual

-- | Message identifier.
type DnsId = Word16

-- | Resource Record type.
data DnsType α where
  -- IPv4 address record (/A/)
  AddrDnsType  ∷ DnsType IP4
  -- IPv6 address record (/AAAA/)
  Addr6DnsType ∷ DnsType IP6
  -- Name server record (/NS/)
  NsDnsType    ∷ DnsType HostName
  -- Canonical name record (/CNAME/)
  CNameDnsType ∷ DnsType HostName
  -- Pointer record (/PTR/)
  PtrDnsType   ∷ DnsType HostName
  -- Mail exchange record (/MX/)
  MxDnsType    ∷ DnsType (Word16, HostName)

#if MIN_VERSION_base(4,7,0)
deriving instance Typeable DnsType
#else
deriving instance Typeable1 DnsType
#endif
deriving instance Eq (DnsType α)

instance Show (DnsType α) where
  showsPrec _ AddrDnsType  = showString "AddrDnsType"
  showsPrec _ Addr6DnsType = showString "Addr6DnsType"
  showsPrec _ NsDnsType    = showString "NsDnsType"
  showsPrec _ CNameDnsType = showString "CNameDnsType"
  showsPrec _ PtrDnsType   = showString "PtrDnsType"
  showsPrec _ MxDnsType    = showString "MxDnsType"

-- | Numeric representation of a Resource Record type.
dnsTypeCode ∷ DnsType α → Word16
dnsTypeCode AddrDnsType  = 1
dnsTypeCode Addr6DnsType = 28
dnsTypeCode NsDnsType    = 2
dnsTypeCode CNameDnsType = 5
dnsTypeCode PtrDnsType   = 12
dnsTypeCode MxDnsType    = 15

-- | Resource Record data.
data DnsData = ∀ α . DnsData { dnsType ∷ !(DnsType α) -- ^ The type
                             , dnsData ∷ α            -- ^ The data
                             }
               deriving Typeable

instance Show DnsData where
  showsPrec p (DnsData {..}) = showParen (p > 10)
      $ showString "DnsData {dnsType = "
      . showsPrec (p + 1) dnsType
      . showString ", dnsData = "
      . case dnsType of
          AddrDnsType  → showsPrec p' dnsData
          Addr6DnsType → showsPrec p' dnsData
          NsDnsType    → showsPrec p' dnsData
          CNameDnsType → showsPrec p' dnsData
          PtrDnsType   → showsPrec p' dnsData
          MxDnsType    → showsPrec p' dnsData
      . showString "}"
    where p' = 10 ∷ Int

-- | Resource Record.
data DnsRecord = DnsRecord { -- | Record owner
                             dnsRecOwner ∷ {-# UNPACK #-} !HostName
                           , -- | Maximum caching time in secords
                             dnsRecTtl   ∷ {-# UNPACK #-} !Word32
                           , -- | Record data
                             dnsRecData  ∷ !DnsData
                           }
                 deriving (Typeable, Show)

serializeDnsRecord ∷ Serializer s ⇒ DnsRecord → CompT s ()
serializeDnsRecord (DnsRecord {..}) | DnsData tp dt ← dnsRecData = do
  serializeHostName dnsRecOwner
  write $  S.word16B (dnsTypeCode tp)
        <> S.word16B 1
        <> S.word32B dnsRecTtl
  incOffset 10
  d ← evalComp $ case tp of
    AddrDnsType  → write (S.put dt) >> incOffset 4
    Addr6DnsType → write (S.put dt) >> incOffset 16
    NsDnsType    → serializeHostName dt
    CNameDnsType → serializeHostName dt
    PtrDnsType   → serializeHostName dt
    MxDnsType    → do
      write $ S.word16B $ fst dt
      incOffset 2
      serializeHostName $ snd dt
  let len = fromIntegral (BSL.length d)
  write $  S.word16B len
        <> S.lazyByteString (BSL.take (fromIntegral len) d)

deserializeDnsRecord ∷ Deserializer μ ⇒ DecompT μ DnsRecord
deserializeDnsRecord = do
  owner ← deserializeHostName
  code  ← lift D.word16B
  void $ lift D.word16B
  ttl   ← lift D.word32B
  len   ← lift D.word16B
  incOffset 10
  dd ← evalDecomp len $ case code of
    1  → DnsData AddrDnsType  <$> (incOffset 4 >> lift D.get)
    2  → DnsData NsDnsType    <$> deserializeHostName
    5  → DnsData CNameDnsType <$> deserializeHostName
    12 → DnsData PtrDnsType   <$> deserializeHostName
    28 → DnsData Addr6DnsType <$> (incOffset 16 >> lift D.get)
    _  → lift $ unexpected $ "Unsupported type " ++ show code
  return $ DnsRecord owner ttl dd

-- | DNS query type.
data DnsQType = ∀ α . StdDnsType (DnsType α) -- ^ Record type
              | AllDnsType -- ^ All record types
              deriving Typeable

instance Show DnsQType where
  showsPrec p (StdDnsType t) = showParen (p > 10)
                             $ showString "StdDnsType "
                             . showsPrec (p + 1) t
  showsPrec _ AllDnsType = showString "AllDnsType"

-- | Numeric representation of a DNS query type.
dnsQTypeCode ∷ DnsQType → Word16
dnsQTypeCode (StdDnsType t) = dnsTypeCode t
dnsQTypeCode AllDnsType     = 255

instance Eq DnsQType where
  t1 == t2 = dnsQTypeCode t1 == dnsQTypeCode t2

instance Ord DnsQType where
  t1 `compare` t2 = dnsQTypeCode t1 `compare` dnsQTypeCode t2

instance Serializable DnsQType where
  put = S.word16B . dnsQTypeCode
  {-# INLINE put #-}

instance SizedSerializable DnsQType where
  size _ = 2
  {-# INLINE size #-}

instance Deserializable DnsQType where
  get = D.word16B >>= \case
    1   → return $ StdDnsType AddrDnsType
    2   → return $ StdDnsType NsDnsType
    5   → return $ StdDnsType CNameDnsType
    12  → return $ StdDnsType PtrDnsType
    28  → return $ StdDnsType Addr6DnsType
    255 → return AllDnsType
    t   → unexpected $ "Unsupported query type" ++ show t

-- | DNS question.
data DnsQuestion = DnsQuestion { -- | Ask about the specified host name
                                 dnsQName ∷ {-# UNPACK #-} !HostName
                               , -- | Query type
                                 dnsQType ∷ !DnsQType
                               }
                   deriving (Typeable, Show, Eq, Ord)

serializeDnsQuestion ∷ Serializer s ⇒ DnsQuestion → CompT s ()
serializeDnsQuestion (DnsQuestion {..}) = do
  serializeHostName dnsQName
  write $  S.put dnsQType
        <> S.word16B 1
  incOffset 4

deserializeDnsQuestion ∷ Deserializer μ ⇒ DecompT μ DnsQuestion
deserializeDnsQuestion = do
  q ← DnsQuestion <$> deserializeHostName <*> lift D.get
  lift $ D.word16B >>= guard "Unsupported class in a question" . (== 1)
  incOffset 4
  return q

-- | Request message.
data DnsReq -- | Standard query
            = DnsReq { -- | Message identifier
                       dnsReqId       ∷ {-# UNPACK #-} !DnsId
                     , -- | Truncation flag
                       dnsReqTruncd   ∷ !Bool
                     , -- | Recursion flag
                       dnsReqRec      ∷ !Bool
                     , -- | Question
                       dnsReqQuestion ∷ {-# UNPACK #-} !DnsQuestion
                     }
            -- | Inverse query
            | DnsInvReq { dnsReqId  ∷ {-# UNPACK #-} !DnsId
                        , -- | IP address
                          dnsReqInv ∷ !IP
                        }
            deriving (Typeable, Show)

anyHostName ∷ HostName
anyHostName = HN "any"

instance Serializable DnsReq where
  put (DnsReq {..})
    =  S.word16B dnsReqId
    <> S.word8 (if dnsReqRec then 1 else 0
                .|. if dnsReqTruncd then 2 else 0)
    <> S.word8 0
    <> S.word16B 1
    <> S.word16B 0
    <> S.word16B 0
    <> S.word16B 0
    <> compress 12 (serializeDnsQuestion dnsReqQuestion)
  put (DnsInvReq {..})
      =  S.word16B dnsReqId
      <> S.word8 8
      <> S.word8 0
      <> S.word16B 0
      <> S.word16B 1
      <> S.word16B 0
      <> S.word16B 0
      <> compress 12 (serializeDnsRecord record)
    where
      record = DnsRecord { dnsRecOwner = anyHostName
                         , dnsRecTtl   = 0
                         , dnsRecData  = case dnsReqInv of
                             IPv4 a → DnsData AddrDnsType a
                             IPv6 a → DnsData Addr6DnsType a }

instance Deserializable DnsReq where
  get = do
    i ← D.word16B
    w ← D.word8
    void D.word8
    guard "Not a request" $ w .&. 128 == 0
    let rec    = w .&. 1 /= 0
        truncd = w .&. 2 /= 0
        opcode = w `shiftR` 3 .&. 0xF
    case opcode of
      0 → do
        D.word16B >>= guard "No questions in query" . (== 1)
        D.word16B >>= guard "Answers in query" . (== 0)
        D.word16B >>= guard "Authorities in query" . (== 0)
        D.word16B >>= guard "Extras in query" . (== 0)
        decompress 12 $ do
          q ← deserializeDnsQuestion
          return $ DnsReq { dnsReqId       = i
                          , dnsReqTruncd   = truncd
                          , dnsReqRec      = rec
                          , dnsReqQuestion = q }
      1 → do
        D.word16B >>= guard "Questions in inverse query" . (== 0)
        D.word16B >>= guard "No answers in inverse query" . (== 1)
        D.word16B >>= guard "Authorities in inverse query" . (== 0)
        D.word16B >>= guard "Extras in inverse query" . (== 0)
        DnsRecord {dnsRecData} ← decompress 12 deserializeDnsRecord
        case dnsRecData of
          DnsData AddrDnsType a →
            return $ DnsInvReq { dnsReqId  = i, dnsReqInv = IPv4 a }
          DnsData Addr6DnsType a →
            return $ DnsInvReq { dnsReqId  = i, dnsReqInv = IPv6 a }
          _ → unexpected "Invalid answer RR in inverse query"
      _ → unexpected $ "Invalid opcode " ++ show opcode ++ " in request"

-- | Errors returned in responses.
data DnsError = FormatDnsError
              | FailureDnsError
              | NoNameDnsError
              | NotImplDnsError
              | RefusedDnsError
              | NameExistsDnsError
              | RsExistsDnsError
              | NoRsDnsError
              | NotAuthDnsError
              | NotInZoneDnsError
              deriving (Typeable, Show, Read, Eq, Ord, Enum)

-- | Numerical representation of the error.
dnsErrorCode ∷ DnsError → Word8
dnsErrorCode FormatDnsError     = 1
dnsErrorCode FailureDnsError    = 2
dnsErrorCode NoNameDnsError     = 3
dnsErrorCode NotImplDnsError    = 4
dnsErrorCode RefusedDnsError    = 5
dnsErrorCode NameExistsDnsError = 6
dnsErrorCode RsExistsDnsError   = 7
dnsErrorCode NoRsDnsError       = 8
dnsErrorCode NotAuthDnsError    = 9
dnsErrorCode NotInZoneDnsError  = 10

-- | Response message.
data DnsResp -- | Normal response.
             = DnsResp { -- | Request identifer
                         dnsRespId       ∷ {-# UNPACK #-} !DnsId
                       , -- | Truncation flag
                         dnsRespTruncd   ∷ !Bool
                       , -- | Authoritative answer flag
                         dnsRespAuthd    ∷ !Bool
                       , -- | Recursive query support flag
                         dnsRespRec      ∷ !Bool
                       , -- | Request question
                         dnsRespQuestion ∷ {-# UNPACK #-} !DnsQuestion
                       , -- | Answer records
                         dnsRespAnswers  ∷ [DnsRecord]
                       , -- | Authority records
                         dnsRespAuths    ∷ [DnsRecord]
                       , -- | Additional records
                         dnsRespExtras   ∷ [DnsRecord]
                       }
             -- | Error response.
             | DnsErrResp { dnsRespId    ∷ {-# UNPACK #-} !DnsId
                          , -- | Error
                            dnsRespError ∷ !DnsError
                          }
             deriving (Typeable, Show)

instance Serializable DnsResp where
  put (DnsResp {..})
      =  S.word16B dnsRespId
      <> S.word8 (128
                  .|. if dnsRespTruncd then 2 else 0
                  .|. if dnsRespAuthd then 4 else 0)
      <> S.word8 (if dnsRespRec then 128 else 0)
      <> S.word16B 1
      <> S.word16B (fromIntegral $ length dnsRespAnswers)
      <> S.word16B (fromIntegral $ length dnsRespAuths)
      <> S.word16B (fromIntegral $ length dnsRespExtras)
      <> compress 12 records
    where records = do
            serializeDnsQuestion dnsRespQuestion
            forM_ dnsRespAnswers serializeDnsRecord
            forM_ dnsRespAuths   serializeDnsRecord
            forM_ dnsRespExtras  serializeDnsRecord
  put (DnsErrResp {..})
    =  S.word16B dnsRespId
    <> S.word8 8
    <> S.word8 (fromIntegral $ dnsErrorCode dnsRespError)
    <> S.word16B 0
    <> S.word16B 0
    <> S.word16B 0
    <> S.word16B 0

instance Deserializable DnsResp where
  get = do
    i ← D.word16B
    w ← D.word8
    guard "Not a response" $ w .&. 128 /= 0
    w' ← D.word8
    let truncd = w .&. 2 /= 0
        authd  = w .&. 4 /= 0
        rec    = w' .&. 128 /= 0
        ec     = w' .&. 0xF
    case ec of
      0 → do
        D.word16B >>= guard "No question in a response" . (== 1)
        anc ← D.word16B
        nsc ← D.word16B
        arc ← D.word16B
        decompress 12 $ do
          q   ← deserializeDnsQuestion
          ans ← mapM (const deserializeDnsRecord) [1 .. anc]
          nss ← mapM (const deserializeDnsRecord) [1 .. nsc]
          ars ← mapM (const deserializeDnsRecord) [1 .. arc]
          return $ DnsResp { dnsRespId       = i
                           , dnsRespTruncd   = truncd
                           , dnsRespAuthd    = authd
                           , dnsRespRec      = rec
                           , dnsRespQuestion = q
                           , dnsRespAnswers  = ans
                           , dnsRespAuths    = nss
                           , dnsRespExtras   = ars }
      _ → do
        void D.word16B
        void D.word16B
        void D.word16B
        void D.word16B
        DnsErrResp i <$> case ec of
          1  → return FormatDnsError
          2  → return FailureDnsError
          3  → return NoNameDnsError
          4  → return NotImplDnsError
          5  → return RefusedDnsError
          6  → return NameExistsDnsError
          7  → return RsExistsDnsError
          8  → return NoRsDnsError
          9  → return NotAuthDnsError
          10 → return NotInZoneDnsError
          _  → unexpected $ "Unknown error code " ++ show ec

