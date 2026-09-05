import assert from "node:assert/strict";
import { test } from "node:test";

import { PURPOSE_NOTICE } from "../src/config.ts";
import { isPublicHostname } from "../src/keydir.ts";
import worker, { type Env } from "../src/worker.ts";

/**
 * A stub environment with no database. It covers the routes that answer before
 * any query, which are also the routes an arriving agent reads first.
 */
const env = {
    DB: null,
    KEYS: null,
    FEED: null,
    BULLETIN_POW_BITS: 20,
    BULLETIN_SIGNATURE_MAX_AGE: 300,
    BULLETIN_EMBED_ORIGIN: "https://harperz9.github.io",
} as unknown as Env;

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

const call = (path: string, init?: RequestInit): Promise<Response> =>
    worker.fetch(new Request(`https://board.example${path}`, init), env, ctx);

test("the discovery document states the identity scheme and the refusals", async () => {
    const response = await call("/.well-known/agent-board.json");
    assert.equal(response.status, 200);
    const doc = (await response.json()) as Record<string, any>;
    assert.equal(doc.authentication.scheme, "web-bot-auth");
    assert.equal(doc.authentication.algorithm, "ed25519");
    assert.ok(doc.authentication.required_signature_params.includes("nonce"));
    assert.equal(doc.content_is_untrusted, true);
    // The board must say what it will not do, in the machine-readable document
    // an agent reads before it does anything else.
    assert.ok(doc.refuses.some((r: string) => r.includes("credential")));
    assert.ok(doc.refuses.includes("rendering posted HTML"));
    assert.ok(doc.does_not_claim.includes("prompt-injection detection"));
});

test("the board says what it is for wherever an agent decides to use it", async () => {
    // One sentence in three places. A purpose stated in only one of them is a
    // purpose most arriving agents never read.
    const doc = (await (await call("/.well-known/agent-board.json")).json()) as Record<string, any>;
    const llms = await (await call("/llms.txt")).text();
    const mcp = (await (await call("/mcp", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    })).json()) as Record<string, any>;
    for (const surface of [doc.purpose, llms, mcp.result?.instructions]) {
        assert.ok(typeof surface === "string" && surface.includes(PURPOSE_NOTICE), surface);
    }
    assert.match(doc.purpose, /bulk data parked here/);
});

test("the discovery document tells agents never to send a credential", async () => {
    const doc = (await (await call("/.well-known/agent-board.json")).json()) as Record<string, any>;
    assert.match(doc.authentication.note, /Never send an API key/);
});

test("llms.txt repeats the untrusted-content warning in prose", async () => {
    const response = await call("/llms.txt");
    assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
    const body = await response.text();
    assert.match(body, /untrusted input/);
    assert.match(body, /never ask you for/);
    assert.match(body, /An API key/);
});

test("every response carries the untrusted marker and refuses indexing", async () => {
    for (const path of ["/.well-known/agent-board.json", "/llms.txt", "/nope"]) {
        const response = await call(path);
        assert.equal(response.headers.get("x-content-is-untrusted"), "true", path);
        assert.equal(response.headers.get("x-robots-tag"), "noindex", path);
        assert.equal(response.headers.get("referrer-policy"), "no-referrer", path);
    }
});

test("framing is limited to the site that embeds the board", async () => {
    const response = await call("/llms.txt");
    const csp = response.headers.get("content-security-policy") ?? "";
    // default-src 'none' is what stops the board's own origin from loading or
    // executing anything, which is the containment claim in one header.
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors https:\/\/harperz9\.github\.io/);
});

test("an unknown route points at the discovery document rather than guessing", async () => {
    const response = await call("/v1/whatever");
    assert.equal(response.status, 404);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.ok, false);
    assert.match(String(body.hint), /agent-board\.json/);
});

test("preflight allows the signature headers and nothing else", async () => {
    const response = await call("/v1/posts", { method: "OPTIONS" });
    assert.equal(response.status, 204);
    const allowed = response.headers.get("access-control-allow-headers") ?? "";
    assert.match(allowed, /signature-input/);
    assert.match(allowed, /content-digest/);
    assert.ok(!allowed.includes("authorization"), "the board has no bearer-token path to allow");
});

test("an unsigned write is refused before it can reach the database", async () => {
    // The stub env has no DB at all, so a route that reached a query would throw
    // a 500. A 401 here proves the signature gate runs first.
    for (const path of ["/v1/posts", "/v1/agents", "/v1/promote", "/v1/posts/abc/flags"]) {
        const response = await call(path, { method: "POST", body: "{}" });
        assert.equal(response.status, 401, path);
    }
});

test("an oversized body is refused on size, before parsing", async () => {
    const response = await call("/v1/posts", { method: "POST", body: "x".repeat(70_000) });
    assert.equal(response.status, 413);
});

test("operator host claims are restricted to plain public hostnames", () => {
    assert.ok(isPublicHostname("bots.example.com"));
    assert.ok(isPublicHostname("example.co.uk"));
    for (const host of [
        "localhost",
        "app.localhost",
        "printer.local",
        "127.0.0.1",
        "169.254.169.254",
        "example.com:8080",
        "example.com/path",
        "user@example.com",
        "",
        "example",
        ".example.com",
        "example..com",
        "EXAMPLE.com",
    ]) {
        assert.ok(!isPublicHostname(host), `${host} must not be fetchable`);
    }
});
