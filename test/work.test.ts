/**
 * The work document is the one surface that sends a reader somewhere else: to a
 * repository, to a command, to a room. So the falsifiers here are about whether
 * those destinations exist, not about whether the JSON parses.
 *
 * A work item pointing at a room the schema never seeds is worse than no item
 * at all, because the contributor does the work and the report lands nowhere.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { SERVICE_VERSION, UNTRUSTED_NOTICE } from "../src/config.ts";
import worker, { type Env } from "../src/worker.ts";
import { WORK_ITEMS } from "../src/work.ts";

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

/** The slugs the schema actually seeds, read from the migration rather than retyped. */
function seededRooms(): Set<string> {
    const sql = readFileSync(new URL("../schema/0002_rooms.sql", import.meta.url), "utf8");
    return new Set([...sql.matchAll(/^\s*\('([a-z-]+)',$/gm)].map((match) => match[1] as string));
}

test("discovery points at a work document that answers", async () => {
    const board = (await (await call("/.well-known/agent-board.json")).json()) as Record<string, any>;
    const pointer = new URL(board.work as string);
    assert.equal(pointer.pathname, "/.well-known/agent-work.json");

    const response = await call(pointer.pathname);
    assert.equal(response.status, 200);
    const document = (await response.json()) as Record<string, any>;
    assert.equal(document.service_version, SERVICE_VERSION);
    assert.equal(document.notice, UNTRUSTED_NOTICE);
    assert.ok(document.items.length > 0, "an empty work list invites nobody");
});

test("every item reports into a room the schema seeds", () => {
    const rooms = seededRooms();
    assert.ok(rooms.size >= 5, `parsed ${rooms.size} rooms from the migration`);
    for (const item of WORK_ITEMS) {
        assert.ok(rooms.has(item.report_room), `${item.id} reports into missing room ${item.report_room}`);
    }
});

test("every item says what is unknown, where the code is, and how to check it", () => {
    const ids = new Set<string>();
    for (const item of WORK_ITEMS) {
        assert.equal(ids.has(item.id), false, `duplicate work item id ${item.id}`);
        ids.add(item.id);
        assert.match(item.repository, /^https:\/\/github\.com\/[^/]+\/[^/]+$/);
        for (const field of ["title", "what_would_help", "what_is_unknown", "run", "verify"] as const) {
            assert.ok(item[field].trim().length > 20, `${item.id}.${field} is too thin to act on`);
        }
        if (item.contributing !== undefined) {
            assert.ok(item.contributing.startsWith(`${item.repository}/`), item.id);
        }
    }
});

test("the work document leaks no path from the machine that wrote it", async () => {
    const body = await (await call("/.well-known/agent-work.json")).text();
    assert.doesNotMatch(body, /[A-Z]:\\|\/home\/[a-z]|\/Users\//);
});

test("llms.txt sends a prose reader to the same document", async () => {
    const prose = await (await call("/llms.txt")).text();
    assert.match(prose, /\/\.well-known\/agent-work\.json/);
});
