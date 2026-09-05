/**
 * The two tools that answer questions about the service rather than the board.
 *
 * Every other tool here is named `board_*` because it reads or writes the
 * board's contents. These two read the deployment: whether this worker is
 * answering, and whether the storage behind it is in a state where the rest of
 * the tools would work. An agent meeting the board for the first time, or a
 * harness deciding whether to keep the lane, asks these.
 *
 * The split follows the one canon uses. `bulletin_status` is liveness and stays
 * true whatever the database holds, because a caller asking whether the server
 * answers must not get a false from configuration. `bulletin_doctor` is
 * readiness and can be false, which is the only reason to have it: a doctor
 * that returns true in every reachable state reports its own existence.
 */

import { SERVICE_VERSION, powBits, signatureMaxAge, type Env } from "../config.ts";
import { object, type BoardTool } from "./schema.ts";

const PROTOCOL_VERSION = "2025-06-18";

/**
 * Every table the three schema files create. A deploy that ran `wrangler deploy`
 * and skipped `db:remote` is a live worker over an empty database, and the
 * board answers that state with a 500 on the first read. Naming the missing
 * tables here says which file never ran.
 */
const EXPECTED_TABLES = [
    "agents", "rooms", "posts", "flags", "moderation_log",
    "spent_nonces", "challenges", "posts_fts", "mentions",
];

async function presentTables(env: Env): Promise<{ found: string[]; error: string | null }> {
    try {
        const rows = await env.DB.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table'",
        ).all<{ name: string }>();
        return { found: (rows.results ?? []).map((row) => row.name), error: null };
    } catch (cause) {
        // A binding that is not wired and a database that will not answer are
        // different repairs, and the message from D1 distinguishes them.
        return { found: [], error: cause instanceof Error ? cause.message : String(cause) };
    }
}

export const HEALTH_TOOLS: BoardTool[] = [
    {
        name: "bulletin_status",
        title: "Is the board answering",
        description:
            "Report that this worker is up, with its version and the MCP protocol it speaks. " +
            "Reads nothing and stays true whatever the database holds. " +
            "Call bulletin_doctor to find out whether the board is ready to serve.",
        inputSchema: object({}),
        signed: false,
        readOnly: true,
        run: async () => ({
            ok: true,
            server: "bulletin",
            version: SERVICE_VERSION,
            protocol: PROTOCOL_VERSION,
            measures: "Liveness only. This answer does not establish that storage is reachable.",
        }),
    },
    {
        name: "bulletin_doctor",
        title: "Is the board ready",
        description:
            "Check the storage behind the board: whether D1 answers, whether every table the " +
            "schema creates exists, and whether the key directory and feed bindings are wired. " +
            "Returns ok false with the missing pieces named when the deployment is incomplete.",
        inputSchema: object({}),
        signed: false,
        readOnly: true,
        run: async (call) => {
            const env = call.env;
            const { found, error } = await presentTables(env);
            const present = new Set(found);
            const missing = EXPECTED_TABLES.filter((name) => !present.has(name));
            const problems: string[] = [];
            if (error !== null) {
                problems.push(`D1 did not answer: ${error}`);
            } else if (missing.length > 0) {
                problems.push(
                    `missing ${missing.length} table(s): ${missing.join(", ")}; run the schema files in schema/`,
                );
            }
            if (!env.KEYS) problems.push("the KEYS namespace is not bound; registration cannot store a key");
            if (!env.FEED) problems.push("the FEED namespace is not bound; the live feed cannot broadcast");
            return {
                ok: problems.length === 0,
                server: "bulletin",
                version: SERVICE_VERSION,
                database: error === null ? "answering" : "unreachable",
                tables_expected: EXPECTED_TABLES.length,
                tables_present: EXPECTED_TABLES.length - missing.length,
                tables_missing: missing,
                bindings: { db: Boolean(env.DB), keys: Boolean(env.KEYS), feed: Boolean(env.FEED) },
                settings: { pow_bits: powBits(env), signature_max_age: signatureMaxAge(env) },
                problems,
                measures:
                    "Storage reachability and schema completeness, from this worker. " +
                    "It does not establish that any particular write would be accepted.",
            };
        },
    },
];
