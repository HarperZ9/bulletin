/**
 * Two things a deploy can get wrong that no other test here would notice.
 *
 * The first is the migration list. `db:local` and `db:remote` are two hand
 * written strings naming the same schema files, and the remote one was missing
 * `0005_rotation.sql` while the code that needs that table was already merged.
 * A board brought up from the remote list would have answered every rotation
 * request with a database error.
 *
 * The second is the version. Four feature pull requests landed on top of 0.2.0
 * without moving it, so the contract reported the same number for a board that
 * carries media and a board that has never heard of it. A client caching by
 * version has no way to tell those apart. The fix is not a rule that says to
 * remember; it is a pin over the surface the board advertises, which fails the
 * moment a route, a tool, or an operation is added or removed.
 *
 * Neither test reaches the network. Both read the same modules the worker
 * serves from.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { SERVICE_VERSION, type Env } from "../src/config.ts";
import { discoveryDocument } from "../src/discovery.ts";
import { openApiDocument } from "../src/openapi.ts";
import { listTools } from "../src/tools.ts";

const ROOT = new URL("../", import.meta.url);

/**
 * The advertised surface, pinned. Bump SERVICE_VERSION and re-pin whenever a
 * route, an MCP tool, or an OpenAPI operation is added, renamed, or dropped.
 */
const REVIEWED_SURFACE_SHA256 =
    "fdc45d3616c17e7b29323e25dfe576c71139e8e7a3738948a85944a4643775ba";

/** Media is an optional binding, so the surface differs by deployment. Both are covered. */
const WITHOUT_MEDIA = { BULLETIN_POW_BITS: 20, BULLETIN_SIGNATURE_MAX_AGE: 300 } as unknown as Env;
const WITH_MEDIA = { ...WITHOUT_MEDIA, MEDIA: {} } as unknown as Env;

function schemaFilesFrom(script: string): string[] {
    const names: string[] = [];
    for (const match of script.matchAll(/schema\/([0-9]+_[a-z0-9_]+\.sql)/g)) {
        if (match[1]) names.push(match[1]);
    }
    return names;
}

function surfaceRecords(env: Env, label: string): string[] {
    const url = new URL("https://board.example/");
    const contract = discoveryDocument(url, env) as Record<string, unknown>;
    const endpoints = contract.endpoints as Record<string, string>;
    const media = contract.media as { enabled: boolean };
    const openapi = openApiDocument(url, env) as { paths: Record<string, Record<string, unknown>> };
    const records = [
        // The media routes are advertised whether or not a bucket is bound, so
        // their names cannot tell a caller that uploads work. The enabled flag
        // is the one honest signal, and leaving it out of the pin would let a
        // bucketless board and a working one hash the same.
        `${label}\tmedia_enabled\t${media.enabled}`,
        ...Object.keys(endpoints).map((name) => `${label}\tendpoint\t${name}`),
        ...listTools().map((tool) => `${label}\ttool\t${tool.name}`),
    ];
    for (const [path, operations] of Object.entries(openapi.paths)) {
        for (const method of Object.keys(operations)) {
            records.push(`${label}\toperation\t${method.toUpperCase()} ${path}`);
        }
    }
    return records.sort();
}

function surfaceFingerprint(): string {
    const records = [
        ...surfaceRecords(WITHOUT_MEDIA, "base"),
        ...surfaceRecords(WITH_MEDIA, "media"),
    ];
    return createHash("sha256").update(records.join("\n") + "\n").digest("hex");
}

test("both migration lists apply every schema file, in order", () => {
    const pkg = JSON.parse(readFileSync(new URL("package.json", ROOT), "utf-8"));
    const onDisk = readdirSync(new URL("schema/", ROOT))
        .filter((name) => name.endsWith(".sql"))
        .sort();
    assert.ok(onDisk.length > 0, "no schema files were found to check against");
    for (const script of ["db:local", "db:remote"]) {
        assert.deepEqual(
            schemaFilesFrom(pkg.scripts[script]),
            onDisk,
            `${script} does not apply every schema file in order`,
        );
    }
});

test("the advertised surface still hashes to the reviewed pin", () => {
    // What fails here is a surface change that went out under an unchanged
    // version. Re-pinning without bumping SERVICE_VERSION defeats the point.
    assert.equal(
        surfaceFingerprint(),
        REVIEWED_SURFACE_SHA256,
        `the advertised surface moved while the version reads ${SERVICE_VERSION}; `
            + "bump SERVICE_VERSION and package.json, then re-pin REVIEWED_SURFACE_SHA256",
    );
});

test("the pin covers whether media is on, not only that the route is listed", () => {
    // A false-success control, and the first run of it earned its place: the
    // fingerprint originally folded route names alone, and the two deployments
    // hashed identically because the routes are published either way. A pin
    // that cannot separate a board accepting uploads from one refusing them
    // would go green on exactly the deploy this file exists to catch.
    const base = surfaceRecords(WITHOUT_MEDIA, "x");
    const withMedia = surfaceRecords(WITH_MEDIA, "x");
    assert.notDeepEqual(base, withMedia, "the fingerprint cannot see the media binding");
    assert.ok(base.includes("x\tmedia_enabled\tfalse"), "a board with no bucket reports media on");
    assert.ok(withMedia.includes("x\tmedia_enabled\ttrue"), "a board with a bucket reports media off");
    assert.ok(
        withMedia.some((record) => record.includes("/v1/media")),
        "no media operation reached the fingerprint",
    );
});
