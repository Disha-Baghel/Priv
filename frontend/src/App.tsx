import { useEffect, useMemo, useRef, useState } from 'react';
import type { FormEvent, KeyboardEvent } from 'react';
import { io, Socket } from 'socket.io-client';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:3000';
const SIGNALING_NS = `${API_BASE}/signaling`;
const TOKEN_STORAGE_KEY = 'priv_access_token';

type User = { id: string; name: string; email: string };
type AuthResponse = { accessToken: string };
type MessageItem = {
  id: string;
  senderId: string;
  receiverId: string;
  text: string;
  createdAt: string;
};
type CipherPayload = { iv: string; data: string };

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return `${parts[0]![0]!}${parts[parts.length - 1]![0]!}`.toUpperCase();
}

function statusPillClass(status: string): string {
  if (status.includes('failed') || status.includes('closed') || status.includes('Decrypt')) return 'status-pill warn';
  if (status.includes('ended') || status.includes('Reconnect')) return 'status-pill warn';
  if (
    status.includes('DataChannel open') ||
    status.startsWith('Peer: connected') ||
    status.includes('E2EE key established') ||
    status === 'Authenticated'
  )
    return 'status-pill ok';
  return 'status-pill';
}

function jwkFingerprint(jwk: JsonWebKey): string {
  const keys = Object.keys(jwk).sort() as (keyof JsonWebKey)[];
  const sorted: Record<string, unknown> = {};
  for (const k of keys) sorted[k as string] = jwk[k];
  return JSON.stringify(sorted);
}

function toB64(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function fromB64(value: string): ArrayBuffer {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return bytes.buffer;
}

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
}

async function exportPublicKey(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key);
}

async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

async function deriveSharedKey(privateKey: CryptoKey, remotePublicKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: remotePublicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encrypt(sharedKey: CryptoKey, plainText: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plainText);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, encoded);
  const payload: CipherPayload = { iv: toB64(iv.buffer), data: toB64(encrypted) };
  return JSON.stringify(payload);
}

async function decrypt(sharedKey: CryptoKey, encryptedJson: string): Promise<string> {
  const payload = JSON.parse(encryptedJson) as CipherPayload;
  const iv = new Uint8Array(fromB64(payload.iv));
  const data = fromB64(payload.data);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sharedKey, data);
  return new TextDecoder().decode(decrypted);
}

function waitSocketConnect(socket: Socket): Promise<void> {
  if (socket.connected) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const ms = 20000;
    const to = window.setTimeout(() => {
      socket.off('connect', ok);
      socket.off('connect_error', err);
      reject(new Error('Signaling socket connect timeout'));
    }, ms);
    const ok = () => {
      window.clearTimeout(to);
      socket.off('connect_error', err);
      resolve();
    };
    const err = (e: Error) => {
      window.clearTimeout(to);
      socket.off('connect', ok);
      reject(e);
    };
    socket.once('connect', ok);
    socket.once('connect_error', err);
  });
}

async function api<T>(path: string, method = 'GET', token?: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = text;
  }
  if (!response.ok) {
    const msg =
      typeof parsed === 'object' && parsed !== null && 'message' in parsed
        ? String((parsed as { message: unknown }).message)
        : text || `${response.status}`;
    throw new Error(msg);
  }
  return parsed as T;
}

function SendIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function App() {
  const [sessionReady, setSessionReady] = useState<boolean>(false);
  const [token, setToken] = useState<string>('');
  const [isRegister, setIsRegister] = useState<boolean>(false);
  const [email, setEmail] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [me, setMe] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [activeUser, setActiveUser] = useState<User | null>(null);
  const [chatInput, setChatInput] = useState<string>('');
  const [messages, setMessages] = useState<MessageItem[]>([]);
  const [status, setStatus] = useState<string>('Disconnected');
  const [authError, setAuthError] = useState<string>('');
  const [authLoading, setAuthLoading] = useState<boolean>(false);
  const [peerTyping, setPeerTyping] = useState<boolean>(false);
  /** Refs do not re-render when the DataChannel opens; track readiness for Send + status. */
  const [e2eeReady, setE2eeReady] = useState<boolean>(false);
  const [dataChannelOpen, setDataChannelOpen] = useState<boolean>(false);
  /** User ended chat or peer ended — no P2P until Reconnect */
  const [p2pSuspended, setP2pSuspended] = useState<boolean>(false);
  /** Bumps to re-run signaling handshake with same contact */
  const [p2pNonce, setP2pNonce] = useState<number>(0);

  const socketRef = useRef<Socket | null>(null);
  const peerRef = useRef<RTCPeerConnection | null>(null);
  const channelRef = useRef<RTCDataChannel | null>(null);
  const localKeyPairRef = useRef<CryptoKeyPair | null>(null);
  const sharedKeyRef = useRef<CryptoKey | null>(null);
  const remotePublicKeyRef = useRef<CryptoKey | null>(null);
  const pendingOfferRef = useRef<RTCSessionDescriptionInit | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const typingClearRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastPeerPubJwkRef = useRef<string>('');
  const clearPkRetryRef = useRef<(() => void) | null>(null);

  const roomId = useMemo(() => {
    if (!me || !activeUser) return '';
    return [me.id, activeUser.id].sort().join(':');
  }, [me, activeUser]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const connectSocket = (accessToken: string) => {
    if (socketRef.current) socketRef.current.disconnect();
    const socket = io(SIGNALING_NS, {
      transports: ['websocket'],
      auth: { token: accessToken },
    });
    socketRef.current = socket;
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const stored = localStorage.getItem(TOKEN_STORAGE_KEY);
      if (!stored) {
        if (!cancelled) setSessionReady(true);
        return;
      }
      try {
        const profile = await api<User>('/users/me', 'GET', stored);
        const usersList = await api<User[]>('/users', 'GET', stored);
        if (cancelled) return;
        setToken(stored);
        connectSocket(stored);
        setMe(profile);
        setUsers(usersList);
        setStatus('Authenticated');
      } catch {
        localStorage.removeItem(TOKEN_STORAGE_KEY);
      } finally {
        if (!cancelled) setSessionReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const resetConnectionState = () => {
    peerRef.current?.close();
    channelRef.current?.close();
    peerRef.current = null;
    channelRef.current = null;
    sharedKeyRef.current = null;
    remotePublicKeyRef.current = null;
    pendingOfferRef.current = null;
    lastPeerPubJwkRef.current = '';
    setPeerTyping(false);
    setE2eeReady(false);
    setDataChannelOpen(false);
  };

  const signOut = () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    socketRef.current?.disconnect();
    socketRef.current = null;
    resetConnectionState();
    setP2pSuspended(false);
    setP2pNonce(0);
    setToken('');
    setMe(null);
    setUsers([]);
    setActiveUser(null);
    setMessages([]);
    setChatInput('');
    setStatus('Disconnected');
    setAuthError('');
  };

  const setupPeer = async (accessToken: string): Promise<RTCPeerConnection> => {
    if (peerRef.current) return peerRef.current;
    const iceConfig = await api<{ iceServers: RTCIceServer[] }>('/webrtc/ice-config', 'GET', accessToken);
    const peer = new RTCPeerConnection({ iceServers: iceConfig.iceServers });
    peer.onicecandidate = (event) => {
      if (!event.candidate || !activeUser) return;
      socketRef.current?.emit('ice-candidate', {
        roomId,
        targetUserId: activeUser.id,
        candidate: event.candidate.toJSON(),
      });
    };
    peer.onconnectionstatechange = () => {
      setStatus(`Peer: ${peer.connectionState}`);
    };
    peer.ondatachannel = (event) => {
      channelRef.current = event.channel;
      bindChannel(event.channel);
    };
    peerRef.current = peer;
    return peer;
  };

  const bindChannel = (channel: RTCDataChannel) => {
    channel.onopen = () => {
      clearPkRetryRef.current?.();
      setDataChannelOpen(true);
      setStatus('DataChannel open — P2P only, no server history');
    };
    channel.onclose = () => {
      setDataChannelOpen(false);
      setStatus('DataChannel closed');
    };
    channel.onmessage = async (event) => {
      if (!sharedKeyRef.current || !me || !activeUser) return;
      try {
        const plaintext = await decrypt(sharedKeyRef.current, event.data as string);
        const now = new Date().toISOString();
        setMessages((prev) => [
          ...prev,
          { id: crypto.randomUUID(), senderId: activeUser.id, receiverId: me.id, text: plaintext, createdAt: now },
        ]);
        socketRef.current?.emit('read-receipt', { roomId, targetUserId: activeUser.id, messageId: `local-${now}` });
      } catch {
        setStatus('Decrypt failed — keys may be out of sync; re-open chat');
      }
    };
  };

  const startCallIfInitiator = async (accessToken: string) => {
    if (!me || !activeUser) return;
    if (me.id.localeCompare(activeUser.id) >= 0) return;
    const peer = await setupPeer(accessToken);
    if (!channelRef.current) {
      const channel = peer.createDataChannel('chat');
      channelRef.current = channel;
      bindChannel(channel);
    }
    if (peer.localDescription) return;
    const offer = await peer.createOffer({
      offerToReceiveAudio: false,
      offerToReceiveVideo: false,
    });
    await peer.setLocalDescription(offer);
    socketRef.current?.emit('offer', { roomId, targetUserId: activeUser.id, sdp: offer });

    const pingKey = async () => {
      if (!localKeyPairRef.current || !socketRef.current?.connected || !activeUser) return;
      const key = await exportPublicKey(localKeyPairRef.current.publicKey);
      socketRef.current.emit('public-key', { roomId, targetUserId: activeUser.id, key });
    };
    void pingKey();
    window.setTimeout(() => void pingKey(), 200);
    window.setTimeout(() => void pingKey(), 600);
    window.setTimeout(() => void pingKey(), 1400);
  };

  const handleAuth = async (event: FormEvent) => {
    event.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const path = isRegister ? '/auth/register' : '/auth/login';
      const payload = isRegister ? { email, name, password } : { email, password };
      const auth = await api<AuthResponse>(path, 'POST', undefined, payload);
      localStorage.setItem(TOKEN_STORAGE_KEY, auth.accessToken);
      setToken(auth.accessToken);
      connectSocket(auth.accessToken);
      const profile = await api<User>('/users/me', 'GET', auth.accessToken);
      const usersList = await api<User[]>('/users', 'GET', auth.accessToken);
      setMe(profile);
      setUsers(usersList);
      setStatus('Authenticated');
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setAuthLoading(false);
    }
  };

  const onSelectUser = async (user: User) => {
    if (!token || !me) return;
    setMessages([]);
    resetConnectionState();
    setP2pSuspended(false);
    setP2pNonce(0);
    localKeyPairRef.current = await generateKeyPair();
    setActiveUser(user);
  };

  const endChatSession = () => {
    if (!activeUser || !me || !socketRef.current) return;
    socketRef.current.emit('session-end', { roomId, targetUserId: activeUser.id });
    resetConnectionState();
    setP2pSuspended(true);
    setStatus('You ended this chat. Tap Reconnect when you are both ready.');
  };

  const reconnectP2P = async () => {
    if (!activeUser || !token || !me) return;
    resetConnectionState();
    localKeyPairRef.current = await generateKeyPair();
    setP2pSuspended(false);
    setP2pNonce((n) => n + 1);
    setStatus('Reconnecting…');
  };

  useEffect(() => {
    if (!socketRef.current || !token || !me) return;
    const socket = socketRef.current;

    const onTyping = (payload: { fromUserId: string; targetUserId: string; isTyping: boolean }) => {
      if (!activeUser || payload.fromUserId !== activeUser.id || payload.targetUserId !== me.id) return;
      if (typingClearRef.current) clearTimeout(typingClearRef.current);
      setPeerTyping(payload.isTyping);
      if (payload.isTyping) {
        typingClearRef.current = setTimeout(() => setPeerTyping(false), 2500);
      }
    };

    socket.on('typing', onTyping);
    return () => {
      socket.off('typing', onTyping);
      if (typingClearRef.current) clearTimeout(typingClearRef.current);
    };
  }, [activeUser, me, token]);

  useEffect(() => {
    if (!socketRef.current || !token || !roomId || !activeUser || !me) return;
    const socket = socketRef.current;

    const onSessionEnd = (payload: { fromUserId: string; targetUserId: string }) => {
      if (payload.targetUserId !== me.id || payload.fromUserId !== activeUser.id) return;
      resetConnectionState();
      setP2pSuspended(true);
      setStatus(`${activeUser.name} ended the chat. Tap Reconnect when you are both ready.`);
    };
    socket.on('session-end', onSessionEnd);

    if (p2pSuspended) {
      clearPkRetryRef.current = null;
      return () => {
        socket.off('session-end', onSessionEnd);
      };
    }

    let cancelled = false;
    let publicKeyInterval: ReturnType<typeof setInterval> | null = null;

    const clearPublicKeyRetry = () => {
      if (publicKeyInterval !== null) {
        clearInterval(publicKeyInterval);
        publicKeyInterval = null;
      }
    };
    clearPkRetryRef.current = clearPublicKeyRetry;

    const applyRemoteOffer = async (sdp: RTCSessionDescriptionInit) => {
      const peer = await setupPeer(token);
      await peer.setRemoteDescription(new RTCSessionDescription(sdp));
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      socket.emit('answer', { roomId, targetUserId: activeUser.id, sdp: answer });

      const pingKey = async () => {
        if (!localKeyPairRef.current) return;
        const key = await exportPublicKey(localKeyPairRef.current.publicKey);
        socket.emit('public-key', { roomId, targetUserId: activeUser.id, key });
      };
      void pingKey();
      window.setTimeout(() => void pingKey(), 200);
      window.setTimeout(() => void pingKey(), 800);
    };

    const emitPublicKey = async () => {
      if (!localKeyPairRef.current) return;
      const key = await exportPublicKey(localKeyPairRef.current.publicKey);
      socket.emit('public-key', { roomId, targetUserId: activeUser.id, key });
    };

    const onOffer = async (payload: { fromUserId: string; targetUserId: string; sdp: RTCSessionDescriptionInit }) => {
      if (payload.targetUserId !== me.id || payload.fromUserId !== activeUser.id) return;
      if (!sharedKeyRef.current) {
        pendingOfferRef.current = payload.sdp;
        setStatus('Waiting for E2EE key before completing WebRTC offer…');
        return;
      }
      await applyRemoteOffer(payload.sdp);
    };

    const onAnswer = async (payload: { fromUserId: string; targetUserId: string; sdp: RTCSessionDescriptionInit }) => {
      if (payload.targetUserId !== me.id || payload.fromUserId !== activeUser.id || !peerRef.current) return;
      await peerRef.current.setRemoteDescription(new RTCSessionDescription(payload.sdp));
    };

    const onCandidate = async (payload: { fromUserId: string; targetUserId: string; candidate: RTCIceCandidateInit }) => {
      if (payload.targetUserId !== me.id || payload.fromUserId !== activeUser.id || !peerRef.current) return;
      try {
        await peerRef.current.addIceCandidate(new RTCIceCandidate(payload.candidate));
      } catch {
        /* ignore */
      }
    };

    const onPublicKey = async (payload: { fromUserId: string; targetUserId: string; key: JsonWebKey }) => {
      if (payload.targetUserId !== me.id || payload.fromUserId !== activeUser.id || !localKeyPairRef.current) return;
      const fp = jwkFingerprint(payload.key);
      if (fp === lastPeerPubJwkRef.current) return;
      lastPeerPubJwkRef.current = fp;

      const pendingOffer = pendingOfferRef.current;
      pendingOfferRef.current = null;

      peerRef.current?.close();
      channelRef.current = null;
      peerRef.current = null;
      setDataChannelOpen(false);

      remotePublicKeyRef.current = await importPublicKey(payload.key);
      sharedKeyRef.current = await deriveSharedKey(localKeyPairRef.current.privateKey, remotePublicKeyRef.current);
      setE2eeReady(true);
      setStatus('E2EE key established — opening data channel…');

      if (pendingOffer) {
        await applyRemoteOffer(pendingOffer);
        return;
      }

      await setupPeer(token);
      await startCallIfInitiator(token);
    };

    socket.on('offer', onOffer);
    socket.on('answer', onAnswer);
    socket.on('ice-candidate', onCandidate);
    socket.on('public-key', onPublicKey);

    const bootstrap = async () => {
      try {
        await waitSocketConnect(socket);
        if (cancelled) return;
        socket.emit('join', { roomId });
        await emitPublicKey();
        if (cancelled) return;
        let pkTicks = 0;
        const PK_MAX = 45;
        publicKeyInterval = setInterval(() => {
          if (cancelled || pkTicks >= PK_MAX) {
            clearPublicKeyRetry();
            if (!cancelled && pkTicks >= PK_MAX) {
              setStatus('No peer public key yet — they should open this chat or tap Reconnect');
            }
            return;
          }
          pkTicks += 1;
          void emitPublicKey();
        }, 800);
      } catch {
        if (!cancelled) setStatus('Signaling failed — check server and refresh');
      }
    };
    void bootstrap();

    return () => {
      cancelled = true;
      clearPublicKeyRetry();
      clearPkRetryRef.current = null;
      if (socket.connected) socket.emit('leave', { roomId });
      socket.off('session-end', onSessionEnd);
      socket.off('offer', onOffer);
      socket.off('answer', onAnswer);
      socket.off('ice-candidate', onCandidate);
      socket.off('public-key', onPublicKey);
    };
  }, [activeUser, me, roomId, token, p2pNonce, p2pSuspended]);

  const sendMessage = async () => {
    if (!chatInput.trim() || !sharedKeyRef.current || !channelRef.current || !activeUser || !me) return;
    if (channelRef.current.readyState !== 'open') return;
    const encrypted = await encrypt(sharedKeyRef.current, chatInput.trim());
    channelRef.current.send(encrypted);
    const now = new Date().toISOString();
    setMessages((prev) => [
      ...prev,
      { id: crypto.randomUUID(), senderId: me.id, receiverId: activeUser.id, text: chatInput.trim(), createdAt: now },
    ]);
    socketRef.current?.emit('typing', { roomId, targetUserId: activeUser.id, isTyping: false });
    setChatInput('');
  };

  const onComposerKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  };

  if (!sessionReady) {
    return (
      <div className="auth-page">
        <div className="auth-card" style={{ textAlign: 'center' }}>
          <p className="auth-tagline" style={{ marginBottom: 0 }}>
            Restoring session…
          </p>
        </div>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="auth-brand">
            <div className="auth-logo">Pr</div>
            <div>
              <h1>Priv</h1>
            </div>
          </div>
          <p className="auth-tagline">
            End-to-end encrypted, real-time chat over WebRTC DataChannels. Signaling only — your messages never touch our
            database.
          </p>
          {authError ? <div className="auth-error">{authError}</div> : null}
          <form onSubmit={handleAuth}>
            <div className="auth-fields">
              {isRegister ? (
                <label>
                  Display name
                  <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Ada Lovelace" required />
                </label>
              ) : null}
              <label>
                Email
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete={isRegister ? 'new-password' : 'current-password'}
                  required
                  minLength={8}
                />
              </label>
            </div>
            <button className="auth-submit" type="submit" disabled={authLoading}>
              {authLoading ? 'Please wait…' : isRegister ? 'Create account' : 'Sign in'}
            </button>
            <button type="button" className="auth-switch" onClick={() => { setIsRegister((v) => !v); setAuthError(''); }}>
              {isRegister ? 'Already have an account? Sign in' : 'New here? Create an account'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const canSend = Boolean(
    activeUser &&
      !p2pSuspended &&
      e2eeReady &&
      dataChannelOpen &&
      sharedKeyRef.current &&
      channelRef.current?.readyState === 'open' &&
      chatInput.trim(),
  );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>Messages</h2>
          {me ? (
            <div className="sidebar-user">
              <div className="avatar" aria-hidden="true">
                {initials(me.name)}
              </div>
              <div className="meta">
                <div className="name">{me.name}</div>
                <div className="email">{me.email}</div>
              </div>
              <button type="button" className="btn-ghost" onClick={signOut}>
                Sign out
              </button>
            </div>
          ) : null}
          <div className={statusPillClass(status)}>
            <span className="dot" />
            <span>{status}</span>
          </div>
        </div>
        {users.length === 0 ? (
          <p className="empty-sidebar">No other users yet. Register a second account in another browser to start a P2P chat.</p>
        ) : (
          <ul className="contact-list">
            {users.map((user) => (
              <li key={user.id}>
                <button
                  type="button"
                  className={`contact-btn ${activeUser?.id === user.id ? 'active' : ''}`}
                  onClick={() => void onSelectUser(user)}
                >
                  <span className="avatar" aria-hidden="true">
                    {initials(user.name)}
                  </span>
                  <span className="contact-text">
                    <span className="title">{user.name}</span>
                    <span className="sub">{user.email}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <main className="thread">
        {activeUser ? (
          <header className="thread-header">
            <div className="thread-header-main">
              <div className="avatar" aria-hidden="true">
                {initials(activeUser.name)}
              </div>
              <div>
                <h3>{activeUser.name}</h3>
                <p className="sub">Encrypted peer-to-peer · not stored on server</p>
              </div>
            </div>
            <div className="thread-actions">
              <button type="button" className="btn-thread primary" onClick={() => void reconnectP2P()}>
                Reconnect
              </button>
              <button type="button" className="btn-thread danger" onClick={endChatSession}>
                End chat
              </button>
            </div>
          </header>
        ) : (
          <header className="thread-header">
            <h3>Select a conversation</h3>
          </header>
        )}

        {!activeUser ? (
          <div className="thread-empty">
            <div className="thread-empty-inner">
              <h3>Welcome back{me ? `, ${me.name.split(' ')[0]}` : ''}</h3>
              <p>Choose someone from the list to establish a secure WebRTC link and chat in real time.</p>
            </div>
          </div>
        ) : (
          <>
            {p2pSuspended ? (
              <div className="chat-banner">
                Chat link is closed on your side or theirs. Both of you can tap <strong>Reconnect</strong> to exchange keys
                and open a new data channel. <strong>End chat</strong> stops the session until you reconnect.
              </div>
            ) : !dataChannelOpen && e2eeReady ? (
              <div className="chat-banner muted">
                Encryption key is ready; waiting for the peer-to-peer data channel. If this stays stuck, both tap{' '}
                <strong>Reconnect</strong>.
              </div>
            ) : null}
            <div className="message-scroll">
              {messages.length === 0 && !p2pSuspended ? (
                <div className="hint-banner">
                  This session is ephemeral. Messages are encrypted with AES-GCM and sent only over the DataChannel — nothing
                  is written to the database.
                </div>
              ) : null}
              {messages.map((message) => (
                <div key={message.id} className={`bubble ${message.senderId === me?.id ? 'mine' : 'theirs'}`}>
                  {message.text}
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
            <div className="typing-indicator">{peerTyping ? `${activeUser.name} is typing…` : '\u00a0'}</div>
            <footer className="composer">
              <textarea
                value={chatInput}
                onChange={(e) => {
                  setChatInput(e.target.value);
                  if (!p2pSuspended) {
                    socketRef.current?.emit('typing', { roomId, targetUserId: activeUser.id, isTyping: true });
                  }
                }}
                onKeyDown={onComposerKeyDown}
                disabled={!activeUser || p2pSuspended}
                placeholder={
                  activeUser
                    ? p2pSuspended
                      ? 'Reconnect to send messages…'
                      : 'Message… (Enter to send, Shift+Enter for newline)'
                    : ''
                }
                rows={1}
              />
              <button
                type="button"
                className="btn-send"
                aria-label="Send message"
                disabled={!canSend}
                onClick={() => void sendMessage()}
              >
                <SendIcon />
              </button>
            </footer>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
