import { createServer } from "http";
import crypto from "crypto";

const PORT = 8000;
const MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SEVEN_BITS_INTEGER_MARKER = 125;
const SIXTEEN_BITS_INTEGER_MARKER = 126;
const SIXTYFOUR_BITS_INTEGER_MARKER = 127;

const FIRST_BIT = 128;
const MASK_KEY_BYTES_INDICATOR = 4;
const MAX_PAYLOAD_SIZE = 64 * 1024 * 1024; // 64 MB max payload

// RFC 6455 opcodes
const OPCODE_CONTINUATION = 0x0;
const OPCODE_TEXT = 0x1;
const OPCODE_BINARY = 0x2;
const OPCODE_CLOSE = 0x8;
const OPCODE_PING = 0x9;
const OPCODE_PONG = 0xa;

const server = createServer((req, res) => {
  res.writeHead(200);
  res.end("successfully received HTTP request");
});

server.listen(PORT, () => {
  console.log(`server listening to port ${PORT}`);
  console.log("http://localhost:8000");
});

server.on("upgrade", onSocketUpgrade);

function onSocketUpgrade(req, socket, head) {
  const { "sec-websocket-key": webClientSocketKey } = req.headers;

  // Validate handshake headers per RFC 6455 §4.2.1
  const upgrade = req.headers["upgrade"];
  const connection = req.headers["connection"];
  const version = req.headers["sec-websocket-version"];

  if (
    req.method !== "GET" ||
    !upgrade ||
    upgrade.toLowerCase() !== "websocket" ||
    !connection ||
    !connection.toLowerCase().includes("upgrade") ||
    version !== "13" ||
    !webClientSocketKey
  ) {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    socket.destroy();
    return;
  }

  console.log(`${webClientSocketKey} websocket connected!`);

  const response_headers = createHandshakeResponse(webClientSocketKey);
  socket.write(response_headers);

  socket.on("readable", () => onSocketReadable(socket));

  socket.on("error", (err) => {
    console.error(`[WS] socket error: ${err.message}`);
  });

  socket.on("close", () => {
    console.log("[WS] connection closed");
  });
}

function onSocketReadable(socket) {
  // Read first byte: FIN (1 bit) + RSV1-3 (3 bits) + Opcode (4 bits)
  const firstByteBuffer = socket.read(1);
  if (!firstByteBuffer) return;

  const firstByte = firstByteBuffer[0];
  const opcode = firstByte & 0x0f;

  // Read second byte: MASK (1 bit) + Payload length indicator (7 bits)
  const secondByteBuffer = socket.read(1);
  if (!secondByteBuffer) return;

  const [MARKER_AND_PAYLOAD_LENGTH] = secondByteBuffer;
  const isMasked = (MARKER_AND_PAYLOAD_LENGTH & FIRST_BIT) !== 0;
  const length_indicator = MARKER_AND_PAYLOAD_LENGTH - FIRST_BIT;

  // Handle close frame (opcode 0x8) — respond with close and tear down
  if (opcode === OPCODE_CLOSE) {
    console.log("[WS] close frame received");
    const closeFrame = Buffer.from([0x88, 0x00]); // FIN + CLOSE, 0 payload
    socket.write(closeFrame);
    socket.end();
    return;
  }

  // Handle ping (opcode 0x9) — respond with pong containing same payload
  if (opcode === OPCODE_PING) {
    const pingLength = length_indicator;
    const maskKey = isMasked ? socket.read(MASK_KEY_BYTES_INDICATOR) : null;
    const payload = pingLength > 0 ? socket.read(pingLength) : Buffer.alloc(0);

    let pongData = payload;
    if (isMasked && maskKey && payload) {
      pongData = decodeMessage(payload, maskKey);
    }

    // Pong frame: FIN + PONG opcode, unmasked, same payload
    const pongHeader = Buffer.from([0x80 | OPCODE_PONG, pongData.length]);
    socket.write(Buffer.concat([pongHeader, pongData]));
    console.log("[WS] ping received, pong sent");
    return;
  }

  // Only process text frames (skip binary/continuation for now)
  if (opcode !== OPCODE_TEXT) {
    console.log(`[WS] unsupported opcode: 0x${opcode.toString(16)}, skipping`);
    return;
  }

  let messageLength = 0;
  if (length_indicator <= SEVEN_BITS_INTEGER_MARKER) {
    messageLength = length_indicator;
  } else if (length_indicator === SIXTEEN_BITS_INTEGER_MARKER) {
    const lenBuf = socket.read(2);
    if (!lenBuf) return;
    messageLength = lenBuf.readUint16BE(0);
  } else {
    const lenBuf = socket.read(8);
    if (!lenBuf) return;
    // readBigUInt64BE returns BigInt — convert to Number (safe up to 2^53)
    messageLength = Number(lenBuf.readBigUInt64BE(0));
  }

  // Reject oversized payloads to prevent OOM
  if (messageLength > MAX_PAYLOAD_SIZE) {
    console.error(`[WS] payload too large: ${messageLength} bytes, closing`);
    const closeFrame = Buffer.from([0x88, 0x02, 0x03, 0xf1]); // close code 1009 (too large)
    socket.write(closeFrame);
    socket.end();
    return;
  }

  const mask_key = isMasked ? socket.read(MASK_KEY_BYTES_INDICATOR) : null;
  const encoded = socket.read(messageLength);
  if (!encoded) return;

  console.log("decoding data...");
  const decoded = isMasked && mask_key ? decodeMessage(encoded, mask_key) : encoded;
  const stringDecoded = decoded.toString("utf8");

  let data;
  try {
    data = JSON.parse(stringDecoded);
  } catch {
    // Not JSON — treat as plain text
    data = stringDecoded;
  }

  console.log("message received!", data);

  const msg = JSON.stringify({
    message: data,
    at: new Date().toISOString(),
  });
  sendMessage(msg, socket);
}

function decodeMessage(encoded, mask_key) {
  const finalBuffer = Buffer.from(encoded);

  for (let index = 0; index < encoded.length; index++) {
    finalBuffer[index] = encoded[index] ^ mask_key[index % 4];
  }

  return finalBuffer;
}

function createHandshakeResponse(socket_key) {
  const webSocket_accept = createSocketAccept(socket_key);

  const response_headers = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${webSocket_accept}`,
    "",
  ];

  return response_headers.join("\r\n") + "\r\n";
}

function createSocketAccept(socket_key) {
  const shaum = crypto.createHash("sha1");
  shaum.update(socket_key + MAGIC_STRING);
  return shaum.digest("base64");
}

function sendMessage(message, socket) {
  const data = prepareMessage(message);
  return socket.write(data);
}

function prepareMessage(message) {
  const msgBuff = Buffer.from(message);
  const msgLength = msgBuff.length;

  const firstByte = 0x80 | OPCODE_TEXT;

  let dataframeHeaderBuffer;

  if (msgLength <= SEVEN_BITS_INTEGER_MARKER) {
    // One-byte payload length
    dataframeHeaderBuffer = Buffer.from([firstByte, msgLength]);
  } else if (msgLength <= 0xffff) {
    // 2-byte extended payload
    dataframeHeaderBuffer = Buffer.alloc(4);
    dataframeHeaderBuffer[0] = firstByte;
    dataframeHeaderBuffer[1] = SIXTEEN_BITS_INTEGER_MARKER;
    dataframeHeaderBuffer.writeUInt16BE(msgLength, 2);
  } else {
    // 8-byte extended payload
    dataframeHeaderBuffer = Buffer.alloc(10);
    dataframeHeaderBuffer[0] = firstByte;
    dataframeHeaderBuffer[1] = SIXTYFOUR_BITS_INTEGER_MARKER;
    dataframeHeaderBuffer.writeBigUInt64BE(BigInt(msgLength), 2);
  }

  const totalLength = dataframeHeaderBuffer.length + msgBuff.length;
  const finalResp = Buffer.concat([dataframeHeaderBuffer, msgBuff], totalLength);

  return finalResp;
}
