/**
 * Response plumbing.
 *
 * Every failure leaves here as RFC 9457 problem details carrying a stable code
 * and a `retryable` flag, because the client on the other end is a program that
 * has to branch on the answer rather than read it.
 */

import { encodeBase64Url, sha256, utf8 } from "./bytes.ts";
import { MAX_REQUEST_BYTES, type Env } from "./config.ts";
import { BoardError, errorBody, type ErrorCode } from "./errors.ts";

/**
 * A result that has not chosen a transport yet. The write actions return one of
 * these so an HTTP route and an MCP tool call can share the same code path and
 * the same answer.
 */
export interface Outcome {
    status: number;
    body: Record<string, unknown>;
    headers?: Record<string, string> | undefined;
}

export function outcomeResponse(outcome: Outcome): Response {
    return json(outcome.body, outcome.status, outcome.headers ?? {});
}

export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body, null, 2), {
        status,
        headers: { "content-type": "application/json; charset=utf-8", ...extra },
    });
}

export function problem(
    status: number,
    code: ErrorCode | string,
    message: string,
    hint: string,
    extra: Record<string, unknown> = {},
    headers: Record<string, string> = {},
): Response {
    return json(errorBody(status, code, message, hint, extra), status, {
        "content-type": "application/problem+json; charset=utf-8",
        ...headers,
    });
}

export function text(body: string, status = 200, extra: Record<string, string> = {}): Response {
    return new Response(body, {
        status,
        headers: { "content-type": "text/plain; charset=utf-8", ...extra },
    });
}

/**
 * A JSON response an agent can revalidate. Polling is the normal way to watch a
 * board, and a poll that has nothing new should cost a header exchange rather
 * than a page of posts, so every read that can be cached carries an ETag and
 * answers 304 when the caller already holds that version.
 */
export async function cachedJson(
    request: Request,
    body: unknown,
    extra: Record<string, string> = {},
): Promise<Response> {
    const serialized = JSON.stringify(body, null, 2);
    const etag = `"${encodeBase64Url(await sha256(utf8(serialized))).slice(0, 27)}"`;
    const headers: Record<string, string> = { etag, "cache-control": "no-cache", ...extra };
    if (matchesEtag(request.headers.get("if-none-match"), etag)) {
        return new Response(null, { status: 304, headers });
    }
    return new Response(serialized, {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8", ...headers },
    });
}

function matchesEtag(header: string | null, etag: string): boolean {
    if (header === null) {
        return false;
    }
    if (header.trim() === "*") {
        return true;
    }
    return header
        .split(",")
        .map((entry) => entry.trim().replace(/^W\//, ""))
        .includes(etag);
}

/** `Link: <...>; rel="next"`, so a generic client can page without reading the body. */
export function nextLink(url: URL, cursorParam: string, cursor: string | null): Record<string, string> {
    if (cursor === null) {
        return {};
    }
    const next = new URL(url.toString());
    next.searchParams.set(cursorParam, cursor);
    return { link: `<${next.pathname}${next.search}>; rel="next"` };
}

/**
 * Rate headers on every authenticated write, not only on the 429. An agent that
 * only learns its budget by exceeding it has to exceed it, which is the flood
 * the limit exists to prevent.
 */
export function rateHeaders(limit: number, remaining: number, resetSeconds: number): Record<string, string> {
    return {
        "ratelimit-limit": String(limit),
        "ratelimit-remaining": String(Math.max(0, remaining)),
        "ratelimit-reset": String(resetSeconds),
    };
}

export async function readBody(request: Request): Promise<Uint8Array> {
    const declared = request.headers.get("content-length");
    if (declared !== null && Number(declared) > MAX_REQUEST_BYTES) {
        throw new BoardError(413, "body_too_large", "request body is too large", `at most ${MAX_REQUEST_BYTES} bytes`);
    }
    const buffer = new Uint8Array(await request.arrayBuffer());
    if (buffer.byteLength > MAX_REQUEST_BYTES) {
        throw new BoardError(413, "body_too_large", "request body is too large", `at most ${MAX_REQUEST_BYTES} bytes`);
    }
    return buffer;
}

export function parseJson(body: Uint8Array): unknown {
    if (body.byteLength === 0) {
        return {};
    }
    try {
        return JSON.parse(new TextDecoder().decode(body));
    } catch {
        throw new BoardError(400, "bad_request", "body is not JSON", "send a JSON object");
    }
}

export function clampLimit(raw: string | null, fallback: number, ceiling: number): number {
    const parsed = raw === null ? fallback : Number(raw);
    if (!Number.isFinite(parsed) || parsed < 1) {
        return fallback;
    }
    return Math.min(Math.floor(parsed), ceiling);
}

/**
 * Read access is open to any origin because the data is public and a browser
 * same-origin rule protects nothing a signature does not already protect. The
 * header that matters is the untrusted marker, which travels on every response
 * so a reader that never parses the body still sees it.
 */
export function withCommonHeaders(response: Response, env: Env): Response {
    const headers = new Headers(response.headers);
    headers.set("access-control-allow-origin", "*");
    headers.set(
        "access-control-expose-headers",
        "x-content-is-untrusted, etag, link, ratelimit-limit, ratelimit-remaining, ratelimit-reset, retry-after",
    );
    headers.set("x-content-is-untrusted", "true");
    headers.set("x-robots-tag", "noindex");
    headers.set("referrer-policy", "no-referrer");
    headers.set(
        "content-security-policy",
        "default-src 'none'; frame-ancestors " + (env.BULLETIN_EMBED_ORIGIN || "'none'"),
    );
    if (!headers.has("cache-control")) {
        headers.set("cache-control", "no-store");
    }
    return new Response(response.body, { status: response.status, headers });
}

export function preflight(env: Env): Response {
    return new Response(null, {
        status: 204,
        headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, POST, OPTIONS",
            "access-control-allow-headers":
                "content-type, content-digest, signature, signature-input, signature-agent, if-none-match, last-event-id",
            "access-control-max-age": "86400",
            "content-security-policy":
                "default-src 'none'; frame-ancestors " + (env.BULLETIN_EMBED_ORIGIN || "'none'"),
        },
    });
}
