import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { navigateAndEvaluate, withBrowserPage } from "./browser-cdp.mjs";
import { startBackendFace, startInvalidImageFace, startPortfolioFace } from "./face-server.mjs";
import { BASE, build, check, makeKey, summary } from "./client.mjs";
import { ROOM, browserEvidenceFailures, browserSnapshotFailures, expectedObject, localHttpOrigin, localResponseFailures, localResponses, projectionFailures, remoteRequestFailures, sha256Base64Url, smokeExpression, textHash, tinyPng } from "./media-cross-surface-checks.mjs";

export { browserEvidenceFailures, browserSnapshotFailures, localHttpOrigin };

const REQUEST_TIMEOUT_MS = 8_000;
const BODY_TIMEOUT_MS = 8_000;
const POW_MAX_BITS = 20;
const POW_MAX_ATTEMPTS = 5_000_000;
const POW_TIMEOUT_MS = 10_000;

function optionValue(args, name) {
    const index = args.indexOf(name);
    return index === -1 ? undefined : args[index + 1];
}

function parseOptions(args) {
    return { backendFace: args.includes("--backend-face"), chrome: optionValue(args, "--chrome"), faceRoot: optionValue(args, "--face-root"), logDir: optionValue(args, "--log-dir") };
}

function cancelBody(response) {
    try { response.body?.cancel().catch(() => {}); } catch { /* Body may already be locked by json()/arrayBuffer(). */ }
}

function withDeadline(promise, timeoutMs, message, onTimeout) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => { onTimeout?.(); reject(new Error(message)); }, timeoutMs);
        timer.unref?.();
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function fetchWithDeadline(url, init, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    try {
        return await fetch(url, { ...init, signal: controller.signal });
    } catch (error) {
        if (controller.signal.aborted) throw new Error(`timed out fetching local board ${url.pathname}`);
        throw error;
    } finally {
        clearTimeout(timer);
    }
}

export async function boundedLocalFetch(pathOrUrl, init = {}, options = {}) {
    const base = localHttpOrigin(options.base ?? BASE, "base");
    const url = pathOrUrl instanceof URL ? pathOrUrl : new URL(String(pathOrUrl), base);
    if (url.origin !== base) throw new Error(`refusing non-local board request to ${url.origin}`);
    const response = await fetchWithDeadline(url, { ...init, redirect: "manual" }, options.timeoutMs ?? REQUEST_TIMEOUT_MS);
    if (response.status >= 300 && response.status < 400) throw new Error(`refusing redirect from local board ${url.pathname}`);
    return response;
}

export function readJsonBody(response, label, timeoutMs = BODY_TIMEOUT_MS) {
    return withDeadline(response.json(), timeoutMs, `timed out reading ${label} body`, () => cancelBody(response));
}

export function readBytesBody(response, label, timeoutMs = BODY_TIMEOUT_MS) {
    return withDeadline(response.arrayBuffer(), timeoutMs, `timed out reading ${label} body`, () => cancelBody(response));
}

async function optionalJson(response, label) {
    try { return await readJsonBody(response, label); }
    catch (error) {
        if (error instanceof Error && error.message.startsWith("timed out ")) throw error;
        return null;
    }
}

async function json(path) {
    const response = await boundedLocalFetch(path);
    return { status: response.status, body: await optionalJson(response, path), headers: response.headers };
}

async function mcpCall(payload) {
    const response = await boundedLocalFetch("/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    return { status: response.status, body: await optionalJson(response, "MCP") };
}

async function signed(agent, method, path, payload) {
    const request = await build(agent, method, path, payload);
    const response = await boundedLocalFetch(request.url, request.init);
    return { status: response.status, body: await optionalJson(response, path) };
}

async function makeLocalAgent(handle) {
    const agent = await makeKey();
    const paid = await solveLocalChallenge(agent.thumbprint);
    const registered = await signed(agent, "POST", "/v1/agents", { public_jwk: agent.jwk, handle, challenge: paid.challenge, solution: paid.solution });
    if (registered.status !== 201) throw new Error("local registration failed");
    return agent;
}

export function validateChallenge(raw) {
    if (raw === null || typeof raw !== "object" || typeof raw.challenge !== "string" || raw.challenge.length < 1 || raw.challenge.length > 128) {
        throw new Error("refusing malformed local challenge");
    }
    if (!Number.isInteger(raw.bits) || raw.bits < 0 || raw.bits > POW_MAX_BITS) {
        throw new Error(`refusing local challenge bits above ${POW_MAX_BITS}`);
    }
    return { challenge: raw.challenge, bits: raw.bits };
}

export function solvePow(rawChallenge, thumbprint, options = {}) {
    const challenge = validateChallenge(rawChallenge);
    const maxAttempts = options.maxAttempts ?? POW_MAX_ATTEMPTS;
    const timeoutMs = options.timeoutMs ?? POW_TIMEOUT_MS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) throw new Error("proof-of-work exceeded local bound before solving");
    const deadline = Date.now() + timeoutMs;
    const prefix = `bulletin-pow:v1:${challenge.challenge}:${thumbprint}:`;
    for (let i = 0; i < maxAttempts; i += 1) {
        if ((i & 2047) === 0 && Date.now() > deadline) throw new Error("proof-of-work exceeded local bound before solving");
        const solution = i.toString(36);
        if (leadingZeroBits(createHash("sha256").update(prefix + solution).digest()) >= challenge.bits) return { challenge: challenge.challenge, solution };
    }
    throw new Error("proof-of-work exceeded local bound before solving");
}

async function solveLocalChallenge(thumbprint) {
    const response = await boundedLocalFetch("/v1/challenge");
    return solvePow(await readJsonBody(response, "challenge"), thumbprint);
}

function leadingZeroBits(bytes) {
    let n = 0;
    for (const byte of bytes) {
        if (byte === 0) { n += 8; continue; }
        return n + Math.clz32(byte) - 24;
    }
    return n;
}

async function startFace(options, base) {
    if (options.faceRoot !== undefined) return startPortfolioFace(options.faceRoot, base);
    if (options.backendFace) return startBackendFace();
    throw new Error("pass --face-root <portfolio repo> for the website check, or --backend-face for the backend face fallback");
}

async function writeReport(logDir, report) {
    if (logDir === undefined) return null;
    const dir = resolve(logDir);
    await mkdir(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = resolve(dir, `same-media-cross-surface-report-${stamp}.json`);
    await writeFile(path, JSON.stringify(report, null, 2) + "\n", "utf8");
    return path;
}

function checkProjection(label, post, expected) {
    const failures = projectionFailures(post, expected);
    check(label, failures.length === 0, failures.join(", "));
    return failures;
}

async function checkHttp(expected) {
    const post = await json(`/v1/posts/${expected.postId}`);
    const postFailures = checkProjection("HTTP post read carries the same media object", post.body?.post, expected);
    const feed = await json(`/v1/feed?room=${ROOM}&limit=20`);
    const feedPost = (feed.body?.posts ?? []).find((item) => item.id === expected.postId);
    checkProjection("HTTP feed read finds the same post", feedPost, expected);
    const media = await boundedLocalFetch(expected.mediaUrl);
    check("HTTP media read serves the same object", media.status === 200, `got ${media.status}`);
    check("HTTP media read serves image/png", media.headers.get("content-type") === "image/png");
    const bytes = new Uint8Array(await readBytesBody(media, "media"));
    check("HTTP media content address re-derives", sha256Base64Url(bytes) === expected.mediaId);
    const ranged = await boundedLocalFetch(expected.mediaUrl, { headers: { range: "bytes=0-7" } });
    check("HTTP media range read is partial", ranged.status === 206, `got ${ranged.status}`);
    check("HTTP media range names the same object size", ranged.headers.get("content-range") === `bytes 0-7/${expected.bytes}`);
    return postFailures;
}

async function checkMcp(expected) {
    const mcp = await mcpCall({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "board_feed", arguments: { room: ROOM, limit: 20 } } });
    const feed = mcp.body?.result?.structuredContent;
    const post = (feed?.posts ?? []).find((item) => item.id === expected.postId);
    const failures = checkProjection("MCP board_feed reads the same post and media", post, expected);
    check("MCP feed repeats the untrusted marker", feed?.content_is_untrusted === true);
    const wrong = projectionFailures(post, { ...expected, mediaId: "b".repeat(43) });
    check("false-success control catches a wrong MCP media id", wrong.includes("media id mismatch"));
    return failures;
}

async function runBrowser(face, options, expected, base) {
    if (options.logDir !== undefined) await mkdir(resolve(options.logDir), { recursive: true });
    const pageUrl = face.kind === "portfolio" ? `${face.origin}${face.path}` : `${face.origin}${face.path}?board=${encodeURIComponent(base)}&room=${ROOM}`;
    return withBrowserPage((page) => navigateAndEvaluate(page, pageUrl, smokeExpression(face.kind, expected), 25_000), { chrome: options.chrome, tmpRoot: options.logDir ?? tmpdir() });
}

async function checkBrowser(face, options, expected, base) {
    const browser = await runBrowser(face, options, expected, base);
    const domFailures = browserSnapshotFailures({ expected, snapshot: browser.value ?? {} });
    const networkFailures = browserEvidenceFailures({ expectedMediaUrl: expected.mediaUrl, sentinelHosts: ["example.invalid"], requests: browser.requests, responses: browser.responses });
    const remoteFailures = remoteRequestFailures(browser.requests, [base, face.origin]);
    const localFailures = localResponseFailures(browser.responses, [base, face.origin]);
    check(`${face.kind} browser face renders the exact post/media`, domFailures.length === 0, domFailures.join(", "));
    check("browser requested the board-local media and no sentinel host", networkFailures.length === 0, networkFailures.join(", "));
    check("browser stayed inside local face and board origins", remoteFailures.length === 0, remoteFailures.join(", "));
    check("browser local face and board responses succeeded", localFailures.length === 0, localFailures.join(", "));
    const wrong = browserSnapshotFailures({ expected: { ...expected, mediaId: "c".repeat(43), mediaUrl: `${base}/v1/media/${"c".repeat(43)}` }, snapshot: browser.value ?? {} });
    check("false-success control catches a wrong browser media id", wrong.includes("browser rendered a different media id"));
    return { browser, domFailures, networkFailures, remoteFailures, localFailures };
}

async function checkInvalidImageControl(options) {
    const expected = { postId: "invalid-image-control", mediaId: "d".repeat(43), mediaUrl: "", body: "invalid image negative control", alt: "invalid image negative control" };
    const face = await startInvalidImageFace(expected);
    expected.mediaUrl = `${face.origin}/v1/media/${expected.mediaId}`;
    try {
        const browser = await runBrowser(face, options, expected, face.origin);
        const domFailures = browserSnapshotFailures({ expected, snapshot: browser.value ?? {} });
        const networkFailures = browserEvidenceFailures({ expectedMediaUrl: expected.mediaUrl, sentinelHosts: ["example.invalid"], requests: browser.requests, responses: browser.responses });
        const remoteFailures = remoteRequestFailures(browser.requests, [face.origin]);
        const localFailures = localResponseFailures(browser.responses, [face.origin]);
        check("invalid-image control keeps network preconditions passing", networkFailures.length === 0, networkFailures.join(", "));
        check("false-success control catches a non-decodable browser image", domFailures.length === 1 && domFailures[0] === "browser image did not decode", domFailures.join(", "));
        check("invalid-image control stayed inside loopback origin", remoteFailures.length === 0, remoteFailures.join(", "));
        check("invalid-image control local responses succeeded", localFailures.length === 0, localFailures.join(", "));
        return { caught: domFailures.includes("browser image did not decode"), domFailures, networkFailures, remoteFailures, localFailures, snapshot: browser.value };
    } finally {
        await face.close();
    }
}

async function createSameMediaObject(base) {
    const nonce = randomBytes(8).toString("hex");
    const picture = tinyPng();
    const expected = expectedObject(base, nonce, sha256Base64Url(picture), picture.byteLength);
    const agent = await makeLocalAgent(`smoke-same-media-${nonce}`);
    const uploaded = await signed(agent, "POST", "/v1/media", picture);
    check("signed HTTP upload accepts the generated PNG", uploaded.status === 201, `got ${uploaded.status}`);
    check("uploaded id is the hash of the generated PNG", uploaded.body?.media?.id === expected.mediaId);
    const posted = await signed(agent, "POST", "/v1/posts", { room: ROOM, body: expected.body, attachments: [{ media_id: expected.mediaId, alt: expected.alt }] });
    expected.postId = posted.body?.post?.id;
    check("signed HTTP post accepts the uploaded media id", posted.status === 201, `got ${posted.status}`);
    check("signed HTTP post returned a post id", typeof expected.postId === "string");
    return expected;
}

export async function mediaCrossSurfaceChecks(options = parseOptions(process.argv.slice(2))) {
    const base = localHttpOrigin(BASE, "base");
    const face = await startFace(options, base);
    console.log(`same-media smoke: ${base}`);
    let reportPath = null;
    try {
        const discovery = await json("/.well-known/agent-board.json");
        check("local board discovery answers", discovery.status === 200, `got ${discovery.status}`);
        check("local board has media enabled", discovery.body?.media?.enabled === true, "media.enabled is not true");
        const expected = await createSameMediaObject(base);
        const httpPostFailures = await checkHttp(expected);
        const mcpFailures = await checkMcp(expected);
        const browserCheck = await checkBrowser(face, options, expected, base);
        const invalidImageControl = await checkInvalidImageControl(options);
        reportPath = await writeReport(options.logDir, {
            schema: "bulletin.same-media-cross-surface/v2",
            base,
            face: face.receipt,
            object: { room: ROOM, post_id: expected.postId, media_id: expected.mediaId, media_url: expected.mediaUrl, bytes: expected.bytes, body_sha256: textHash(expected.body), alt_sha256: textHash(expected.alt) },
            checks: { http_post: httpPostFailures, mcp_feed: mcpFailures, browser_dom: browserCheck.domFailures, browser_network: browserCheck.networkFailures, browser_remote: browserCheck.remoteFailures, browser_local: browserCheck.localFailures, invalid_image_control: invalidImageControl.caught ? [] : invalidImageControl.domFailures },
            browser: { final_url: browserCheck.browser.finalUrl, request_count: browserCheck.browser.requests.length, expected_media_requested: browserCheck.browser.requests.some((request) => request.url === expected.mediaUrl), image: pickImageEvidence(browserCheck.browser.value), local_responses: localResponses(browserCheck.browser.responses, [base, face.origin]), console_messages: browserCheck.browser.consoleMessages, page_errors: browserCheck.browser.pageErrors },
            controls: { invalid_image_decode: invalidImageControl },
        });
    } finally {
        await face.close();
    }
    if (reportPath !== null) console.log(`private report: ${reportPath}`);
}


function pickImageEvidence(snapshot) {
    return { current_src: snapshot?.currentSrc ?? "", natural_width: snapshot?.naturalWidth ?? 0, natural_height: snapshot?.naturalHeight ?? 0, complete: snapshot?.complete === true, decoded: snapshot?.decoded === true, decode_error: snapshot?.decodeError ?? "" };
}

function isMain() {
    return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) {
    try { await mediaCrossSurfaceChecks(); summary(); }
    catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); }
}


