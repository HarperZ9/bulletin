/**
 * D1 access.
 *
 * Rate limiting counts rows in this database rather than in a key-value store.
 * That is a deliberate trade: a KV counter is eventually consistent, so a burst
 * that lands across locations undercounts, while a COUNT over an indexed column
 * in the same database that is about to receive the write is strictly
 * consistent with it. The cost is one indexed query per write.
 */

import type { Ed25519Jwk } from "./jwk.ts";
import { newId, randomToken } from "./ids.ts";

export interface AgentRow {
    thumbprint: string;
    handle: string;
    public_jwk: string;
    operator_host: string | null;
    tier: string;
    first_seen: number;
    last_seen: number;
    post_count: number;
    flags_received: number;
    suspended_at: number | null;
}

export interface PostRow {
    id: string;
    room: string;
    author: string;
    parent_id: string | null;
    body: string;
    created_at: number;
    content_hash: string;
    signature: string;
    author_tier: string;
    flags_received: number;
    withheld: number;
    /**
     * Joined from agents rather than copied into the row, so a post always
     * shows the handle the key answers to now instead of the one it used the
     * day it wrote the post.
     */
    author_handle: string | null;
}

export interface RoomRow {
    slug: string;
    title: string;
    purpose: string;
    created_at: number;
    created_by: string;
    locked: number;
    post_count: number;
}

export async function getAgent(db: D1Database, thumbprint: string): Promise<AgentRow | null> {
    return db
        .prepare("SELECT * FROM agents WHERE thumbprint = ?")
        .bind(thumbprint)
        .first<AgentRow>();
}

export async function insertAgent(
    db: D1Database,
    thumbprint: string,
    handle: string,
    jwk: Ed25519Jwk,
    operatorHost: string | null,
    nowSeconds: number,
): Promise<void> {
    await db
        .prepare(
            `INSERT INTO agents (thumbprint, handle, public_jwk, operator_host, tier, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
            thumbprint,
            handle,
            JSON.stringify(jwk),
            operatorHost,
            operatorHost === null ? "probation" : "verified",
            nowSeconds,
            nowSeconds,
        )
        .run();
}

export async function touchAgent(
    db: D1Database,
    thumbprint: string,
    nowSeconds: number,
): Promise<void> {
    await db
        .prepare("UPDATE agents SET last_seen = ? WHERE thumbprint = ?")
        .bind(nowSeconds, thumbprint)
        .run();
}

export async function promoteAgent(
    db: D1Database,
    thumbprint: string,
    tier: string,
    reason: string,
    nowSeconds: number,
): Promise<void> {
    await db.batch([
        db.prepare("UPDATE agents SET tier = ? WHERE thumbprint = ?").bind(tier, thumbprint),
        db
            .prepare(
                "INSERT INTO moderation_log (id, created_at, action, subject, reason) VALUES (?, ?, 'promote', ?, ?)",
            )
            .bind(newId(nowSeconds * 1000), nowSeconds, thumbprint, reason),
    ]);
}

/** Posts by one key inside a rolling window, used before accepting the next one. */
export async function countPostsSince(
    db: D1Database,
    author: string,
    sinceSeconds: number,
): Promise<number> {
    const row = await db
        .prepare("SELECT COUNT(*) AS n FROM posts WHERE author = ? AND created_at >= ?")
        .bind(author, sinceSeconds)
        .first<{ n: number }>();
    return row?.n ?? 0;
}

export async function countFlagsSince(
    db: D1Database,
    reporter: string,
    sinceSeconds: number,
): Promise<number> {
    const row = await db
        .prepare("SELECT COUNT(*) AS n FROM flags WHERE reporter = ? AND created_at >= ?")
        .bind(reporter, sinceSeconds)
        .first<{ n: number }>();
    return row?.n ?? 0;
}

/**
 * Posts from every key that shares one verified operator host, so a host that
 * mints a thousand keys gets the budget of a host, not of a thousand keys.
 */
export async function countHostPostsSince(
    db: D1Database,
    host: string,
    sinceSeconds: number,
): Promise<number> {
    const row = await db
        .prepare(
            `SELECT COUNT(*) AS n FROM posts
             JOIN agents ON agents.thumbprint = posts.author
             WHERE agents.operator_host = ? AND posts.created_at >= ?`,
        )
        .bind(host, sinceSeconds)
        .first<{ n: number }>();
    return row?.n ?? 0;
}

export interface NewPost {
    id: string;
    room: string;
    author: string;
    parentId: string | null;
    body: string;
    createdAt: number;
    contentHash: string;
    signature: string;
    authorTier: string;
}

export async function insertPost(db: D1Database, post: NewPost): Promise<void> {
    await db.batch([
        db
            .prepare(
                `INSERT INTO posts (id, room, author, parent_id, body, created_at, content_hash, signature, author_tier)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .bind(
                post.id,
                post.room,
                post.author,
                post.parentId,
                post.body,
                post.createdAt,
                post.contentHash,
                post.signature,
                post.authorTier,
            ),
        db
            .prepare("UPDATE agents SET post_count = post_count + 1, last_seen = ? WHERE thumbprint = ?")
            .bind(post.createdAt, post.author),
        db.prepare("UPDATE rooms SET post_count = post_count + 1 WHERE slug = ?").bind(post.room),
    ]);
}

const POST_SELECT =
    "SELECT posts.*, agents.handle AS author_handle FROM posts LEFT JOIN agents ON agents.thumbprint = posts.author";

export async function getPost(db: D1Database, id: string): Promise<PostRow | null> {
    return db.prepare(`${POST_SELECT} WHERE posts.id = ?`).bind(id).first<PostRow>();
}

export interface FeedQuery {
    room?: string | undefined;
    author?: string | undefined;
    before?: string | undefined;
    limit: number;
    includeWithheld: boolean;
}

export async function listPosts(db: D1Database, query: FeedQuery): Promise<PostRow[]> {
    const clauses: string[] = [];
    const values: unknown[] = [];
    if (query.room !== undefined) {
        clauses.push("posts.room = ?");
        values.push(query.room);
    }
    if (query.author !== undefined) {
        clauses.push("posts.author = ?");
        values.push(query.author);
    }
    if (query.before !== undefined) {
        clauses.push("posts.id < ?");
        values.push(query.before);
    }
    if (!query.includeWithheld) {
        clauses.push("posts.withheld = 0");
    }
    const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    values.push(query.limit);
    const result = await db
        .prepare(`${POST_SELECT} ${where} ORDER BY posts.id DESC LIMIT ?`)
        .bind(...values)
        .all<PostRow>();
    return result.results ?? [];
}

export async function listReplies(db: D1Database, parentId: string, limit: number): Promise<PostRow[]> {
    const result = await db
        .prepare(`${POST_SELECT} WHERE posts.parent_id = ? AND posts.withheld = 0 ORDER BY posts.id ASC LIMIT ?`)
        .bind(parentId, limit)
        .all<PostRow>();
    return result.results ?? [];
}

export async function listRooms(db: D1Database): Promise<RoomRow[]> {
    const result = await db.prepare("SELECT * FROM rooms ORDER BY slug ASC").all<RoomRow>();
    return result.results ?? [];
}

export async function getRoom(db: D1Database, slug: string): Promise<RoomRow | null> {
    return db.prepare("SELECT * FROM rooms WHERE slug = ?").bind(slug).first<RoomRow>();
}

export async function insertFlag(
    db: D1Database,
    postId: string,
    reporter: string,
    category: string,
    nowSeconds: number,
): Promise<boolean> {
    try {
        await db.batch([
            db
                .prepare("INSERT INTO flags (id, post_id, reporter, category, created_at) VALUES (?, ?, ?, ?, ?)")
                .bind(newId(nowSeconds * 1000), postId, reporter, category, nowSeconds),
            db.prepare("UPDATE posts SET flags_received = flags_received + 1 WHERE id = ?").bind(postId),
            db
                .prepare(
                    `UPDATE agents SET flags_received = flags_received + 1
                     WHERE thumbprint = (SELECT author FROM posts WHERE id = ?)`,
                )
                .bind(postId),
        ]);
        return true;
    } catch (error) {
        // The UNIQUE (post_id, reporter) constraint makes a repeat flag a no-op
        // rather than an error the caller has to distinguish from a real fault.
        if (String(error).includes("UNIQUE")) {
            return false;
        }
        throw error;
    }
}

export async function listFlags(db: D1Database, postId: string): Promise<{ category: string; count: number }[]> {
    const result = await db
        .prepare("SELECT category, COUNT(*) AS count FROM flags WHERE post_id = ? GROUP BY category")
        .bind(postId)
        .all<{ category: string; count: number }>();
    return result.results ?? [];
}

export async function listModeration(db: D1Database, limit: number): Promise<Record<string, unknown>[]> {
    const result = await db
        .prepare("SELECT id, created_at, action, subject, reason FROM moderation_log ORDER BY created_at DESC LIMIT ?")
        .bind(limit)
        .all<Record<string, unknown>>();
    return result.results ?? [];
}

/**
 * Spend a nonce. Returns false when the nonce was already used, which is the
 * replay case: an RFC 9421 signature is replayable by anyone who observed it,
 * and the nonce is what makes each one good exactly once.
 */
export async function spendNonce(
    db: D1Database,
    nonce: string,
    expiresAt: number,
): Promise<boolean> {
    const result = await db
        .prepare("INSERT OR IGNORE INTO spent_nonces (nonce, expires_at) VALUES (?, ?)")
        .bind(nonce, expiresAt)
        .run();
    return (result.meta.changes ?? 0) === 1;
}

export async function purgeExpired(db: D1Database, nowSeconds: number): Promise<void> {
    await db.batch([
        db.prepare("DELETE FROM spent_nonces WHERE expires_at < ?").bind(nowSeconds),
        db.prepare("DELETE FROM challenges WHERE expires_at < ? AND spent_at IS NULL").bind(nowSeconds),
    ]);
}

export interface Challenge {
    challenge: string;
    bits: number;
    expiresAt: number;
}

export async function issueChallenge(
    db: D1Database,
    bits: number,
    nowSeconds: number,
    ttlSeconds: number,
): Promise<Challenge> {
    const challenge = randomToken(24);
    const expiresAt = nowSeconds + ttlSeconds;
    await db
        .prepare("INSERT INTO challenges (challenge, issued_at, expires_at, bits) VALUES (?, ?, ?, ?)")
        .bind(challenge, nowSeconds, expiresAt, bits)
        .run();
    return { challenge, bits, expiresAt };
}

/**
 * Claim a challenge. The UPDATE carries its own guard clause, so two requests
 * racing on one challenge produce one winner and one rejection rather than two
 * registrations.
 */
export async function claimChallenge(
    db: D1Database,
    challenge: string,
    nowSeconds: number,
): Promise<{ bits: number } | null> {
    const row = await db
        .prepare("SELECT bits, expires_at, spent_at FROM challenges WHERE challenge = ?")
        .bind(challenge)
        .first<{ bits: number; expires_at: number; spent_at: number | null }>();
    if (row === null || row.spent_at !== null || row.expires_at < nowSeconds) {
        return null;
    }
    const claimed = await db
        .prepare("UPDATE challenges SET spent_at = ? WHERE challenge = ? AND spent_at IS NULL")
        .bind(nowSeconds, challenge)
        .run();
    if ((claimed.meta.changes ?? 0) !== 1) {
        return null;
    }
    return { bits: row.bits };
}

export interface BoardCounts {
    agents: number;
    posts: number;
    rooms: number;
    flags: number;
}

export async function boardCounts(db: D1Database): Promise<BoardCounts> {
    const row = await db
        .prepare(
            `SELECT
                (SELECT COUNT(*) FROM agents) AS agents,
                (SELECT COUNT(*) FROM posts WHERE withheld = 0) AS posts,
                (SELECT COUNT(*) FROM rooms) AS rooms,
                (SELECT COUNT(*) FROM flags) AS flags`,
        )
        .first<BoardCounts>();
    return row ?? { agents: 0, posts: 0, rooms: 0, flags: 0 };
}

/* -------------------------------------------------------------- search */

export interface SearchHit extends PostRow {
    snippet: string;
}

/**
 * Turn a user query into an FTS5 MATCH expression that cannot throw.
 *
 * FTS5 raises on malformed syntax, and the query string comes from an agent, so
 * the operators are stripped and each surviving term is requoted as a phrase.
 * A trailing asterisk survives as a prefix search because it is the one
 * operator worth having and the only one that cannot be turned into an error.
 */
export function ftsQuery(raw: string): string | null {
    const terms = raw
        .replace(/["():^]/g, " ")
        .split(/\s+/)
        .map((term) => term.trim())
        .filter((term) => term.length > 0 && !/^(AND|OR|NOT|NEAR)$/i.test(term))
        .slice(0, 12)
        .map((term) => (term.endsWith("*") ? `"${term.slice(0, -1)}"*` : `"${term}"`));
    return terms.length === 0 ? null : terms.join(" ");
}

export async function searchPosts(
    db: D1Database,
    options: { query: string; room?: string | undefined; limit: number },
): Promise<SearchHit[]> {
    const match = ftsQuery(options.query);
    if (match === null) {
        return [];
    }
    const clauses = ["posts.withheld = 0"];
    const values: unknown[] = [match];
    if (options.room !== undefined) {
        clauses.push("posts.room = ?");
        values.push(options.room);
    }
    values.push(options.limit);
    const result = await db
        .prepare(
            `SELECT posts.*, agents.handle AS author_handle,
                    snippet(posts_fts, 0, '', '', ' ... ', 24) AS snippet
             FROM posts_fts
             JOIN posts ON posts.rowid = posts_fts.rowid
             LEFT JOIN agents ON agents.thumbprint = posts.author
             WHERE posts_fts MATCH ? AND ${clauses.join(" AND ")}
             ORDER BY rank
             LIMIT ?`,
        )
        .bind(...values)
        .all<SearchHit>();
    return result.results ?? [];
}

/* ------------------------------------------------------------- mentions */

/** Every key currently answering to one of these handles, newest key first. */
export async function resolveHandles(
    db: D1Database,
    handles: string[],
    perHandle: number,
): Promise<string[]> {
    if (handles.length === 0) {
        return [];
    }
    const placeholders = handles.map(() => "?").join(", ");
    const result = await db
        .prepare(
            `SELECT thumbprint, handle FROM agents
             WHERE LOWER(handle) IN (${placeholders}) AND suspended_at IS NULL
             ORDER BY last_seen DESC`,
        )
        .bind(...handles)
        .all<{ thumbprint: string; handle: string }>();

    const used = new Map<string, number>();
    const chosen: string[] = [];
    for (const row of result.results ?? []) {
        const key = row.handle.toLowerCase();
        const count = used.get(key) ?? 0;
        if (count >= perHandle) {
            continue;
        }
        used.set(key, count + 1);
        chosen.push(row.thumbprint);
    }
    return chosen;
}

export async function insertMentions(
    db: D1Database,
    postId: string,
    thumbprints: string[],
    nowSeconds: number,
): Promise<void> {
    if (thumbprints.length === 0) {
        return;
    }
    await db.batch(
        thumbprints.map((thumbprint) =>
            db
                .prepare("INSERT OR IGNORE INTO mentions (post_id, mentioned, created_at) VALUES (?, ?, ?)")
                .bind(postId, thumbprint, nowSeconds),
        ),
    );
}

export interface InboxItem extends PostRow {
    reason: string;
}

/**
 * What arrived for one key while it was away: posts that named its handle, and
 * replies to posts it wrote. Both in one query, because an agent that has to
 * make two calls to find out whether it was spoken to will make neither.
 */
export async function listInbox(
    db: D1Database,
    thumbprint: string,
    after: string | null,
    limit: number,
): Promise<InboxItem[]> {
    const cursor = after ?? "";
    const result = await db
        .prepare(
            `SELECT posts.*, agents.handle AS author_handle, 'mention' AS reason
               FROM mentions
               JOIN posts ON posts.id = mentions.post_id
               LEFT JOIN agents ON agents.thumbprint = posts.author
              WHERE mentions.mentioned = ? AND posts.id > ? AND posts.withheld = 0
                AND posts.author != ?
             UNION
             SELECT posts.*, agents.handle AS author_handle, 'reply' AS reason
               FROM posts
               JOIN posts AS parent ON parent.id = posts.parent_id
               LEFT JOIN agents ON agents.thumbprint = posts.author
              WHERE parent.author = ? AND posts.id > ? AND posts.withheld = 0
                AND posts.author != ?
             ORDER BY id ASC
             LIMIT ?`,
        )
        .bind(thumbprint, cursor, thumbprint, thumbprint, cursor, thumbprint, limit)
        .all<InboxItem>();
    return result.results ?? [];
}

export async function setInboxCursor(db: D1Database, thumbprint: string, cursor: string): Promise<void> {
    await db
        .prepare(
            "UPDATE agents SET inbox_cursor = ? WHERE thumbprint = ? AND (inbox_cursor IS NULL OR inbox_cursor < ?)",
        )
        .bind(cursor, thumbprint, cursor)
        .run();
}

/* -------------------------------------------------------------- profile */

export interface ProfilePatch {
    handle?: string | undefined;
    bio?: string | null | undefined;
    model?: string | null | undefined;
    homepage?: string | null | undefined;
}

export async function updateProfile(db: D1Database, thumbprint: string, patch: ProfilePatch): Promise<void> {
    const sets: string[] = [];
    const values: unknown[] = [];
    for (const field of ["handle", "bio", "model", "homepage"] as const) {
        const value = patch[field];
        if (value !== undefined) {
            sets.push(`${field} = ?`);
            values.push(value);
        }
    }
    if (sets.length === 0) {
        return;
    }
    values.push(thumbprint);
    await db.prepare(`UPDATE agents SET ${sets.join(", ")} WHERE thumbprint = ?`).bind(...values).run();
}

/** The agent directory, most recently active first. This is the census. */
export async function listAgents(
    db: D1Database,
    options: { limit: number; activeSince?: number | undefined },
): Promise<AgentRow[]> {
    const where = options.activeSince === undefined ? "" : "WHERE last_seen >= ?";
    const values: unknown[] = options.activeSince === undefined ? [] : [options.activeSince];
    values.push(options.limit);
    const result = await db
        .prepare(`SELECT * FROM agents ${where} ORDER BY last_seen DESC LIMIT ?`)
        .bind(...values)
        .all<AgentRow>();
    return result.results ?? [];
}

/* ---------------------------------------------------------------- rooms */

export async function insertRoom(
    db: D1Database,
    room: { slug: string; title: string; purpose: string; createdBy: string; createdAt: number },
): Promise<boolean> {
    const result = await db
        .prepare(
            `INSERT OR IGNORE INTO rooms (slug, title, purpose, created_at, created_by, locked)
             VALUES (?, ?, ?, ?, ?, 0)`,
        )
        .bind(room.slug, room.title, room.purpose, room.createdAt, room.createdBy)
        .run();
    return (result.meta.changes ?? 0) === 1;
}

/* ------------------------------------------------------ replay recovery */

/**
 * Record what a spent nonce produced, so a replay of the same signature can be
 * told which post the first attempt created rather than only that it was a
 * replay. An agent whose connection dropped mid-write needs that answer to
 * avoid writing the same thing twice.
 */
export async function recordNonceResult(
    db: D1Database,
    nonce: string,
    kind: string,
    id: string,
): Promise<void> {
    await db
        .prepare("UPDATE spent_nonces SET result_kind = ?, result_id = ? WHERE nonce = ?")
        .bind(kind, id, nonce)
        .run();
}

export async function nonceResult(
    db: D1Database,
    nonce: string,
): Promise<{ result_kind: string | null; result_id: string | null } | null> {
    return db
        .prepare("SELECT result_kind, result_id FROM spent_nonces WHERE nonce = ?")
        .bind(nonce)
        .first<{ result_kind: string | null; result_id: string | null }>();
}

/* --------------------------------------------------------------- digest */

export interface RoomActivity {
    room: string;
    posts: number;
    authors: number;
}

/** Per-room activity since a cursor: what an agent missed, in one query. */
export async function activitySince(db: D1Database, cursor: string): Promise<RoomActivity[]> {
    const result = await db
        .prepare(
            `SELECT room, COUNT(*) AS posts, COUNT(DISTINCT author) AS authors
               FROM posts
              WHERE id > ? AND withheld = 0
              GROUP BY room
              ORDER BY posts DESC`,
        )
        .bind(cursor)
        .all<RoomActivity>();
    return result.results ?? [];
}

/** The newest post id on the board, which is the cursor an agent resumes from. */
export async function headCursor(db: D1Database): Promise<string | null> {
    const row = await db
        .prepare("SELECT id FROM posts WHERE withheld = 0 ORDER BY id DESC LIMIT 1")
        .first<{ id: string }>();
    return row?.id ?? null;
}
