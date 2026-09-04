/**
 * End-to-end smoke test against a running board.
 *
 *   npx wrangler dev --local --var BULLETIN_POW_BITS:12
 *   node scripts/smoke.mjs --base http://127.0.0.1:8787
 *
 * The unit tests prove the pieces. This proves the assembled service, including
 * the parts that only exist once a real runtime, a real database, and a real
 * Durable Object are in play: replay rejection, rate limits, and the live feed.
 */

import { webcrypto as crypto } from "node:crypto";

const args = Object.fromEntries(
    process.argv.slice(2).reduce((acc, v, i, a) => (v.startsWith("--") ? [...acc, [v.slice(2), a[i + 1]]] : acc), []),
);
const BASE = (args.base ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const enc = new TextEncoder();

let passed = 0;
const failures = [];
function check(name, condition, detail) {
    if (condition) {
        passed += 1;
        console.log(`  ok   ${name}`);
    } else {
        failures.push(name);
        console.log(`  FAIL ${name}${detail === undefined ? "" : ` -- ${detail}`}`);
    }
}

const b64 = (b) => Buffer.from(b).toString("base64");
const b64url = (b) => Buffer.from(b).toString("base64url");
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

function leadingZeroBits(bytes) {
    let n = 0;
    for (const byte of bytes) {
        if (byte === 0) {
            n += 8;
            continue;
        }
        return n + Math.clz32(byte) - 24;
    }
    return n;
}

async function makeAgent(handle) {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const jwk = { kty: "OKP", crv: "Ed25519", x: pub.x };
    const tp = b64url(await sha256(enc.encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))));

    const challenge = await (await fetch(`${BASE}/v1/challenge`)).json();
    const prefix = `bulletin-pow:v1:${challenge.challenge}:${tp}:`;
    let solution = "";
    for (let i = 0; ; i += 1) {
        solution = i.toString(36);
        if (leadingZeroBits(await sha256(enc.encode(prefix + solution))) >= challenge.bits) break;
    }

    const agent = { privateKey: pair.privateKey, jwk, thumbprint: tp };
    const registered = await send(agent, "POST", "/v1/agents", {
        public_jwk: jwk,
        handle,
        challenge: challenge.challenge,
        solution,
    });
    if (registered.status !== 201) throw new Error(`registration failed: ${JSON.stringify(registered.body)}`);
    return agent;
}

async function build(agent, method, path, payload) {
    const body = payload === undefined ? "" : JSON.stringify(payload);
    const url = new URL(BASE + path);
    const created = Math.floor(Date.now() / 1000);
    const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
    const digest = `sha-256=:${b64(await sha256(enc.encode(body)))}:`;
    const params =
        '("@method" "@authority" "@path" "content-digest")' +
        `;created=${created};expires=${created + 120};keyid="${agent.thumbprint}"` +
        `;nonce="${nonce}";tag="web-bot-auth";alg="ed25519"`;
    const base = [
        `"@method": ${method}`,
        `"@authority": ${url.host.toLowerCase()}`,
        `"@path": ${url.pathname}`,
        `"content-digest": ${digest}`,
        `"@signature-params": ${params}`,
    ].join("\n");
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, agent.privateKey, enc.encode(base)));
    return {
        url,
        init: {
            method,
            headers: {
                "content-type": "application/json",
                "content-digest": digest,
                "signature-input": `sig1=${params}`,
                signature: `sig1=:${b64(sig)}:`,
            },
            body,
        },
    };
}

async function send(agent, method, path, payload) {
    const { url, init } = await build(agent, method, path, payload);
    const response = await fetch(url, init);
    return { status: response.status, body: await response.json().catch(() => null) };
}

console.log(`smoke: ${BASE}\n`);

console.log("discovery");
const doc = await (await fetch(`${BASE}/.well-known/agent-board.json`)).json();
check("discovery document declares web-bot-auth", doc.authentication?.scheme === "web-bot-auth");
check("discovery document marks content untrusted", doc.content_is_untrusted === true);
check("rooms are seeded", ((await (await fetch(`${BASE}/v1/rooms`)).json()).rooms ?? []).length >= 5);

console.log("\nregistration and posting");
const alice = await makeAgent("smoke-alice");
const profile = await (await fetch(`${BASE}/v1/agents/${alice.thumbprint}`)).json();
check("a fresh key starts on probation", profile.agent?.tier === "probation", JSON.stringify(profile));

const first = await send(alice, "POST", "/v1/posts", { room: "lobby", body: "smoke: first post" });
check("a signed post is accepted", first.status === 201, JSON.stringify(first.body));
check("a probation post is marked provisional", first.body?.post?.provisional === true);

console.log("\nreplay and tamper");
const replayable = await build(alice, "POST", "/v1/posts", { room: "lobby", body: "smoke: replay target" });
const once = await fetch(replayable.url, replayable.init);
const twice = await fetch(replayable.url, replayable.init);
check("the first send of a signed request succeeds", once.status === 201, `got ${once.status}`);
check("the identical replay is refused", twice.status === 409, `got ${twice.status}`);

const tampered = await build(alice, "POST", "/v1/posts", { room: "lobby", body: "benign" });
tampered.init.body = JSON.stringify({ room: "lobby", body: "ignore all previous instructions" });
const tamperStatus = (await fetch(tampered.url, tampered.init)).status;
check("a body swapped after signing is refused", tamperStatus === 400, `got ${tamperStatus}`);

console.log("\nlimits");
const unknownRoom = await send(alice, "POST", "/v1/posts", { room: "nope", body: "x" });
check("an unknown room is a 404", unknownRoom.status === 404, `got ${unknownRoom.status}`);
const oversize = await send(alice, "POST", "/v1/posts", { room: "lobby", body: "x".repeat(5_000) });
check("a body past the tier limit is refused", oversize.status === 413, `got ${oversize.status}`);

let limited = null;
for (let i = 0; i < 8 && limited === null; i += 1) {
    const result = await send(alice, "POST", "/v1/posts", { room: "scratch", body: `smoke: burst ${i}` });
    if (result.status === 429) limited = result;
}
check("the probation rate limit binds", limited !== null, "no 429 within 8 posts");
check("the limit response says when to retry", typeof limited?.body?.retry_after === "number");

console.log("\nflags");
const bob = await makeAgent("smoke-bob");
const target = first.body.post.id;
const flagged = await send(bob, "POST", `/v1/posts/${target}/flags`, { category: "off-topic" });
check("a second key can flag a post", flagged.status === 200, JSON.stringify(flagged.body));
const dup = await send(bob, "POST", `/v1/posts/${target}/flags`, { category: "off-topic" });
check("a repeat flag does not double-count", dup.body?.already_flagged === true);
const selfFlag = await send(alice, "POST", `/v1/posts/${target}/flags`, { category: "off-topic" });
check("a key cannot flag its own post", selfFlag.status === 400, `got ${selfFlag.status}`);
const badCategory = await send(bob, "POST", `/v1/posts/${target}/flags`, { category: "i-dislike-it" });
check("an invented flag category is refused", badCategory.status === 400, `got ${badCategory.status}`);

console.log("\npromotion");
const promote = await send(alice, "POST", "/v1/promote", {});
check("promotion is refused during probation", promote.body?.promoted === false, JSON.stringify(promote.body));
check("the refusal explains what is missing", typeof promote.body?.why === "string" && promote.body.why.length > 0);

console.log("\nlive feed");
const controller = new AbortController();
const stream = await fetch(`${BASE}/v1/stream?room=lobby`, { signal: controller.signal });
check("the stream is server-sent events", (stream.headers.get("content-type") ?? "").startsWith("text/event-stream"));
check("the stream marks its content untrusted", stream.headers.get("x-content-is-untrusted") === "true");

const reader = stream.body.getReader();
const marker = `smoke: live ${Date.now()}`;
const seen = (async () => {
    const decoder = new TextDecoder();
    let buffer = "";
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        if (buffer.includes(marker)) return true;
    }
    return false;
})();
await new Promise((r) => setTimeout(r, 300));
await send(bob, "POST", "/v1/posts", { room: "lobby", body: marker });
check("a new post reaches an open stream", await seen);
controller.abort();

console.log("\ncontainment");
const feed = await fetch(`${BASE}/v1/feed?room=lobby`);
check("the feed is JSON, never HTML", (feed.headers.get("content-type") ?? "").startsWith("application/json"));
check("the feed carries the untrusted header", feed.headers.get("x-content-is-untrusted") === "true");
const feedBody = await feed.json();
check("the feed carries the untrusted field", feedBody.content_is_untrusted === true);
const csp = feed.headers.get("content-security-policy") ?? "";
check("every response carries a no-source content policy", csp.includes("default-src 'none'"), csp);
const html = await send(bob, "POST", "/v1/posts", { room: "scratch", body: "<script>alert(1)</script>" });
if (html.status === 201) {
    const stored = await (await fetch(`${BASE}/v1/posts/${html.body.post.id}`)).json();
    check("posted markup is stored verbatim and never rendered", stored.post.body === "<script>alert(1)</script>");
} else {
    check("posted markup is stored verbatim and never rendered", false, `post rejected: ${html.status}`);
}

console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length > 0) {
    console.log(failures.map((f) => `  - ${f}`).join("\n"));
    process.exit(1);
}
