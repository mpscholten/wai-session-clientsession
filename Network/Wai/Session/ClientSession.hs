{-# LANGUAGE LambdaCase #-}

module Network.Wai.Session.ClientSession (clientsessionStore) where

import Control.Monad
import Data.ByteString (ByteString)
import Control.Monad.IO.Class (liftIO, MonadIO)
import Network.Wai.Session (Session, SessionStore)
import Data.IORef
import Control.Error (hush)

import Web.ClientSession (Key, encryptIO, decrypt)
import Data.Serialize (encode, decode, Serialize) -- Use cereal because clientsession does

-- | Session store that keeps all content in a 'Serialize'd cookie encrypted
-- with 'Web.ClientSession'
--
-- Decryption is deferred until the session is first read or written.
-- The Set-Cookie header is skipped when the session is never accessed.
--
-- WARNING: This session is vulnerable to sidejacking,
-- use with TLS for security.
clientsessionStore :: (Serialize k, Serialize v, Eq k, MonadIO m) => Key -> SessionStore m k v
clientsessionStore cryptKey maybeCookie = do
	-- Pure + lazy: decryption thunk evaluated only when initialPairs is forced
	let initialPairs = case maybeCookie of
		Nothing -> []
		Just encoded -> case hush . decode =<< decrypt cryptKey encoded of
			Just sessionData -> sessionData
			Nothing -> []

	-- Nothing = never accessed; Just (pairs, dirty) = accessed
	ref <- newIORef Nothing

	let ensureLoaded = readIORef ref >>= \case
		Just (pairs, _) -> pure pairs
		Nothing -> do
			writeIORef ref (Just (initialPairs, False))
			pure initialPairs

	return ((
			(\k -> lookup k `liftM` liftIO ensureLoaded),
			(\k v -> liftIO $ do
				pairs <- ensureLoaded
				writeIORef ref (Just (((k,v):) . filter ((/=k) . fst) $ pairs, True)))
		), readIORef ref >>= \case
			Nothing            -> return Nothing      -- never accessed: skip Set-Cookie
			Just (_, False)    -> return maybeCookie   -- read-only: echo original bytes
			Just (pairs, True) -> Just <$> (encryptIO cryptKey $ encode pairs)
		)
