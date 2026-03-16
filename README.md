<p align="center">
  <h1 align="center">RFC 6455 WebSocket Server</h1>
  <p align="center">
    From-Scratch Protocol Implementation
    <br />
    <strong>Zero Dependencies &middot; Binary Frame Parsing &middot; Full Handshake</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-22+-339933?style=flat-square&logo=node.js" alt="Node.js" />
  <img src="https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/RFC-6455-blue?style=flat-square" alt="RFC 6455" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" />
</p>

---

## What is this?

A WebSocket server built **entirely from scratch** using only Node.js built-in modules (`http`, `crypto`). No `ws`, no `socket.io`, no external libraries — every byte of the WebSocket protocol is parsed and constructed manually.

This is an educational implementation that demonstrates exactly what happens under the hood when a browser opens a WebSocket connection: the HTTP upgrade handshake, the SHA-1 challenge/response, binary frame parsing with variable-length payloads, and the XOR masking algorithm that protects against cache poisoning attacks.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
  - [The Handshake](#1-the-handshake)
  - [Frame Format](#2-frame-format)
  - [Masking Algorithm](#3-masking-algorithm)
  - [Message Flow](#4-message-flow)
- [RFC 6455 Compliance](#rfc-6455-compliance)
- [File Structure](#file-structure)
- [License](#license)

---

## Features

- **Full HTTP/1.1 101 Upgrade** — Validates GET method, `Upgrade`, `Connection`, and `Sec-WebSocket-Version` headers per RFC 6455 §4.2.1
- **SHA-1 Challenge Handshake** — Computes `Sec-WebSocket-Accept` from the client's key + GUID constant
- **Variable-Length Frame Parser** — Handles all three payload length encodings: 7-bit (≤125 bytes), 16-bit (≤64 KiB), and 64-bit (≤64 MB with safety cap)
- **4-Byte XOR Masking** — Client-to-server frames unmasked per RFC 6455 §5.3; server-to-client frames sent unmasked (per spec)
- **Control Frame Support** — Handles Close (0x8) with proper close response and Ping/Pong (0x9/0xA) for keepalive
- **Payload Size Protection** — Rejects payloads exceeding 64 MB with close code 1009 (Message Too Big)
- **JSON Echo Server** — Parses incoming JSON, echoes back with server timestamp

---

## Quick Start

```sh
git clone https://github.com/MFZNK05/WebSocket_Raw.git
cd WebSocket_Raw
node server.mjs
```

```
server listening to port 8000
http://localhost:8000
```

Open `index.html` in a browser, or connect programmatically:

```sh
node client.mjs
```

### Browser Console Test

```javascript
const ws = new WebSocket("ws://localhost:8000");
ws.onmessage = (e) => console.log(JSON.parse(e.data));
ws.onopen = () => ws.send(JSON.stringify({ hello: "world" }));
```

---

## How It Works

### 1. The Handshake

When a browser sends a WebSocket connection request, it starts as a regular HTTP GET with special headers:

```
GET / HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

The server must prove it understands WebSocket by computing a challenge response:

```
Sec-WebSocket-Accept = Base64(SHA-1(client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

The GUID `258EAFA5-E914-47DA-95CA-C5AB0DC85B11` is a fixed constant defined in RFC 6455. It exists solely to prevent non-WebSocket servers from accidentally accepting WebSocket connections.

```javascript
function createSocketAccept(socket_key) {
  const shaum = crypto.createHash("sha1");
  shaum.update(socket_key + MAGIC_STRING);
  return shaum.digest("base64");
}
```

The server responds with HTTP 101:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

After this, the TCP connection switches from HTTP text to the WebSocket binary frame protocol.

### 2. Frame Format

Every WebSocket message is wrapped in a binary frame:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

**Payload length encoding (3 tiers):**

| Indicator | Meaning | Max Size |
|-----------|---------|----------|
| 0–125 | Length is the value itself | 125 bytes |
| 126 | Next 2 bytes are the length (UInt16BE) | 65,535 bytes |
| 127 | Next 8 bytes are the length (UInt64BE) | 2^63 bytes |

**Opcodes:**

| Opcode | Frame Type | Description |
|--------|-----------|-------------|
| `0x0` | Continuation | Fragment of a multi-frame message |
| `0x1` | Text | UTF-8 encoded text data |
| `0x2` | Binary | Raw binary data |
| `0x8` | Close | Connection close request |
| `0x9` | Ping | Keepalive probe |
| `0xA` | Pong | Keepalive response |

### 3. Masking Algorithm

RFC 6455 §5.3 mandates that all client-to-server frames are masked with a 4-byte key. Server-to-client frames are **never** masked. This asymmetry exists to prevent proxy cache poisoning attacks.

```
For each byte i in the payload:
    decoded[i] = encoded[i] XOR mask_key[i % 4]
```

The 4-byte mask key rotates cyclically. The same operation applies for both masking and unmasking (XOR is its own inverse).

```javascript
function decodeMessage(encoded, mask_key) {
  const finalBuffer = Buffer.from(encoded);
  for (let index = 0; index < encoded.length; index++) {
    finalBuffer[index] = encoded[index] ^ mask_key[index % 4];
  }
  return finalBuffer;
}
```

### 4. Message Flow

```
Browser                                    Server
   │                                         │
   │──── HTTP GET (Upgrade: websocket) ─────>│
   │                                         │  Validate headers
   │                                         │  SHA-1(key + GUID)
   │<─── HTTP 101 Switching Protocols ───────│
   │                                         │
   │──── [FIN=1, OPCODE=0x1, MASK=1,        │
   │      mask_key, payload] ───────────────>│  XOR unmask
   │                                         │  JSON.parse
   │<─── [FIN=1, OPCODE=0x1, MASK=0,        │
   │      payload] ──────────────────────────│  Echo + timestamp
   │                                         │
   │──── [FIN=1, OPCODE=0x9 (PING)] ───────>│
   │<─── [FIN=1, OPCODE=0xA (PONG)] ────────│  Auto-reply
   │                                         │
   │──── [FIN=1, OPCODE=0x8 (CLOSE)] ──────>│
   │<─── [FIN=1, OPCODE=0x8 (CLOSE)] ───────│  Echo close
   │              connection closed           │
```

---

## RFC 6455 Compliance

| Feature | Section | Status |
|---------|---------|--------|
| HTTP/1.1 Upgrade handshake | §4.2.1 | Implemented |
| Sec-WebSocket-Accept challenge | §4.2.2 | Implemented |
| Header validation (method, version) | §4.2.1 | Implemented |
| Text frames (opcode 0x1) | §5.6 | Implemented |
| Close frames (opcode 0x8) | §5.5.1 | Implemented |
| Ping/Pong (opcode 0x9/0xA) | §5.5.2 | Implemented |
| 7-bit payload length | §5.2 | Implemented |
| 16-bit payload length | §5.2 | Implemented |
| 64-bit payload length | §5.2 | Implemented |
| Client-to-server masking | §5.3 | Implemented |
| Server-to-client unmasked | §5.1 | Implemented |
| Payload size limit (1009) | §7.4.1 | Implemented |
| Binary frames (opcode 0x2) | §5.6 | Not implemented |
| Fragmentation (opcode 0x0) | §5.4 | Not implemented |
| Per-message compression | §9.1 | Not implemented |
| Subprotocol negotiation | §4.2.2 | Not implemented |

---

## File Structure

```
WebSocket_Raw/
├── server.mjs     Server — handshake, frame parser, masking, echo response
├── client.mjs     Node.js test client (programmatic WebSocket connection)
├── index.html     Browser test page (connects via native WebSocket API)
└── package.json   Project metadata (zero dependencies)
```

---

## License

This project is open source under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Zero dependencies. Every byte parsed by hand.</sub>
</p>
