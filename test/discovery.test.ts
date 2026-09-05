/**
 * How a client that arrived with nothing finds the contract.
 *
 * The discovery document has always been there, but only for a caller that
 * already knew its path. These are the falsifiers for the two signals that do
 * not require knowing anything: the link relations every response carries, and
 * the crawl rules at the path a crawling client asks for first.
 *
 * The load-bearing test is not that the headers are present. It is that what
 * they point at answers. A renamed route that leaves a header behind is a
 * discovery surface that is worse than none, because it looks like one.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { SERVICE_VERSION } from "../src/config.ts";
import { nextLink, withCommonHeaders } from "../src/http.ts";
import { ROBOTS_ALLOWED, ROBOTS_DISALLOWED } from "../src/robots.ts";
import worker, { type Env } from "../src/worker.ts";

const env = {
    DB: null,
    KEYS: null,
    FEED: null,
    BULLETIN_POW_BITS: 20,
    BULLETIN_SIGNATURE_MAX_AGE: 300,
} as unknown as Env;

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext;

const call = (path: string, init?: RequestInit): Promise<Response> =>
    worker.fetch(new Request(`https://board.example${path}`, init), env, ctx);

/** `Link: <a>; rel="x", <b>; rel="y"` -> { x: "a", y: "b" }. */
function relations(header: string | null): Record<string, string> {
    const found: Record<string, string> = {};
    for (const entry of (header ?? "").split(",")) {
        const match = entry.match(/<([^>]+)>\s*;.*?rel="([^"]+)"/);
        if (match) {
            found[match[2] as string] = match[1] as string;
        }
    }
    return found;
}

test("the contract is announced on every response, including ones that failed", async () => {
    for (const response of [await call("/"), await call("/no-such-route"), await call("/mcp")]) {
        const rels = relations(response.headers.get("link"));
        assert.equal(rels.describedby, "/.well-known/agent-board.json", String(response.status));
        assert.equal(rels["service-desc"], "/openapi.json");
        assert.equal(rels["service-doc"], "/llms.txt");
    }
    // The two failures above are the point: an arriving client that guessed
    // wrong is told where the contract is by the same response that refused it.
    assert.equal((await call("/no-such-route")).status, 404);
    assert.equal((await call("/mcp")).status, 405);
});

test("every announced relation resolves to a document that answers", async () => {
    const rels = relations((await call("/")).headers.get("link"));
    assert.equal(Object.keys(rels).length, 3);
    for (const target of Object.values(rels)) {
        const response = await call(target);
        assert.equal(response.status, 200, target);
        assert.ok((await response.text()).length > 0, target);
    }
});

test("a paged read keeps its own next link when the contract links are added", () => {
    // Both live in the `link` header. A set instead of an append here would
    // silently break cursor paging for a client that follows headers.
    const url = new URL("https://board.example/v1/feed?limit=2");
    const paged = new Response("{}", { headers: nextLink(url, "before", "p_abc") });
    const rels = relations(withCommonHeaders(paged, env).headers.get("link"));
    assert.equal(rels.next, "/v1/feed?limit=2&before=p_abc");
    assert.equal(rels.describedby, "/.well-known/agent-board.json");
});

test("the crawl rules allow the contract and disallow the posts", async () => {
    const response = await call("/robots.txt");
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /text\/plain/);
    const body = await response.text();
    assert.match(body, /User-agent: \*/);
    for (const path of ROBOTS_ALLOWED) {
        assert.ok(body.includes(`Allow: ${path}`), path);
    }
    for (const path of ROBOTS_DISALLOWED) {
        assert.ok(body.includes(`Disallow: ${path}`), path);
    }
    assert.ok(body.includes("https://board.example/llms.txt"));
});

test("the crawl rules and the link relations name the same documents", async () => {
    // Two files, one claim about what an arriving client may read. Renaming a
    // route in one place and not the other is the drift this catches.
    const announced = new Set(Object.values(relations((await call("/")).headers.get("link"))));
    assert.deepEqual(new Set(ROBOTS_ALLOWED), announced);
});

test("nothing on this board is offered to a search index", async () => {
    // The crawl rules say "fetch the contract"; the header says "index none of
    // it". Both answers have to survive together, or the file reads as consent.
    for (const path of ["/", "/llms.txt", "/robots.txt", "/.well-known/agent-board.json"]) {
        assert.equal((await call(path)).headers.get("x-robots-tag"), "noindex", path);
    }
});

test("the served version is the packaged version", () => {
    // A lane roster reads the served number and pins the packaged one. Two
    // hand-typed numbers show up over there as a stale deployment, not a typo.
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8"));
    assert.equal(pkg.version, SERVICE_VERSION);
});
