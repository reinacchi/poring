// Independent RFC 8441 interoperability client (Node.js `http2`, which uses nghttp2 —
// not the Rust `h2` crate used by Poring). Usage: node h2_ws_client.mjs <host:port> <path>
//
// Steps: h2c prior-knowledge connection; wait for SETTINGS_ENABLE_CONNECT_PROTOCOL;
// Extended CONNECT (:protocol websocket); exchange masked WebSocket frames on the stream
// (text, binary, ping); close with 1000 and expect the echoed close; plain GET on the same
// connection. Prints one JSON line with the results and exits 0 only if all checks pass.
import http2 from "node:http2";
import crypto from "node:crypto";

const [target, path = "/echo"] = process.argv.slice(2);
if (!target) {
  console.error("usage: node h2_ws_client.mjs <host:port> [path]");
  process.exit(2);
}
const results = {};
const fail = (msg) => {
  console.log(JSON.stringify({ ok: false, error: msg, results }));
  process.exit(1);
};
setTimeout(() => fail("timeout"), 10000).unref();

function frame(opcode, payload) {
  const len = payload.length;
  const head = [0x80 | opcode];
  if (len < 126) head.push(0x80 | len);
  else if (len < 65536) head.push(0x80 | 126, len >> 8, len & 0xff);
  else throw new Error("too big for this client");
  const mask = crypto.randomBytes(4);
  const body = Buffer.from(payload).map((b, i) => b ^ mask[i % 4]);
  return Buffer.concat([Buffer.from(head), mask, body]);
}

// Minimal frame parser for unmasked server frames.
function* parse(buf) {
  let off = 0;
  while (buf.length - off >= 2) {
    const b0 = buf[off], b1 = buf[off + 1];
    if (b1 & 0x80) throw new Error("server frame is masked");
    let len = b1 & 0x7f, hdr = 2;
    if (len === 126) { if (buf.length - off < 4) break; len = buf.readUInt16BE(off + 2); hdr = 4; }
    else if (len === 127) { if (buf.length - off < 10) break; len = Number(buf.readBigUInt64BE(off + 2)); hdr = 10; }
    if (buf.length - off < hdr + len) break;
    yield { fin: !!(b0 & 0x80), opcode: b0 & 0x0f, payload: buf.subarray(off + hdr, off + hdr + len) };
    off += hdr + len;
  }
  return off;
}

const session = http2.connect(`http://${target}`);
session.on("error", (e) => fail(`session error: ${e.message}`));
session.on("remoteSettings", (settings) => {
  results.enableConnectProtocol = settings.enableConnectProtocol === true;
  if (!results.enableConnectProtocol) fail("server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL");
  if (results.started) return;
  results.started = true;
  const req = session.request({
    ":method": "CONNECT",
    ":protocol": "websocket",
    ":scheme": "http",
    ":path": path,
    ":authority": target,
    "sec-websocket-version": "13",
  });
  req.on("error", (e) => fail(`stream error: ${e.message}`));
  req.on("response", (headers) => {
    results.status = headers[":status"];
    results.h1Headers = ["upgrade", "connection", "sec-websocket-accept"].filter((h) => h in headers);
    if (results.status !== 200) fail(`status ${results.status}`);
    let pending = Buffer.alloc(0);
    const want = ["text", "binary", "pong", "close"];
    req.on("data", (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      const it = parse(pending);
      let r;
      while (!(r = it.next()).done) {
        const f = r.value;
        if (f.opcode === 1) results.text = f.payload.toString("utf8");
        else if (f.opcode === 2) results.binary = [...f.payload];
        else if (f.opcode === 0xa) results.pong = f.payload.toString("utf8");
        else if (f.opcode === 8) results.closeCode = f.payload.length >= 2 ? f.payload.readUInt16BE(0) : null;
      }
      pending = pending.subarray(r.value);
      if (results.text !== undefined && results.binary && results.pong !== undefined && !results.closeSent) {
        results.closeSent = true;
        const cp = Buffer.alloc(2);
        cp.writeUInt16BE(1000);
        req.write(frame(8, cp));
      }
      if (results.closeCode !== undefined) {
        req.end();
        // Ordinary request on the same HTTP/2 connection.
        const get = session.request({ ":method": "GET", ":path": "/plain" });
        let body = "";
        get.on("data", (d) => (body += d));
        get.on("end", () => {
          results.plain = body;
          const ok =
            results.text === "hello from node" &&
            JSON.stringify(results.binary) === JSON.stringify([1, 2, 3]) &&
            results.pong === "nping" &&
            results.closeCode === 1000 &&
            results.h1Headers.length === 0 &&
            results.plain === "plain";
          console.log(JSON.stringify({ ok, results }));
          session.close();
          process.exit(ok ? 0 : 1);
        });
        get.end();
      }
    });
    req.write(frame(1, Buffer.from("hello from node", "utf8")));
    req.write(frame(2, Buffer.from([1, 2, 3])));
    req.write(frame(9, Buffer.from("nping", "utf8")));
  });
});
