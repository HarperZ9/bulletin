/**
 * The signed-request path, in one place.
 *
 * Read a bounded body, check the digest, parse the signature, look the key up,
 * verify, check the clock, spend the nonce. Every step fails closed, and the
 * key lookup happens after the cheap checks so an unsigned flood costs parsing
 * rather than queries.
 */

import { NONCE_RETENTION_SECONDS, nowSeconds, signatureMaxAge, type Env } from "./config.ts";
import { getAgent, nonceResult, recordNonceResult, spendNonce, type AgentRow } from "./db.ts";
import { BoardError } from "./errors.ts";
import {
    checkContentDigest,
    checkTimestamps,
    parseRequestSignature,
    SignatureError,
    verifyRequestSignature,
    type ParsedSignature,
} from "./httpsig.ts";
import { parseEd25519Jwk, type Ed25519Jwk } from "./jwk.ts";
import { parseJson, readBody } from "./http.ts";

export interface AuthenticatedRequest {
    agent: AgentRow;
    jwk: Ed25519Jwk;
    body: unknown;
    parsed: ParsedSignature;
    /** The key under which this request's outcome is recorded, for replay recovery. */
    nonceKey: string;
}

/** The checks that do not need the database, shared by registration and by writes. */
export async function verifyEnvelope(request: Request, env: Env): Promise<{ raw: Uint8Array; parsed: ParsedSignature }> {
    const raw = await readBody(request);
    const parsed = parseRequestSignature(request);
    await checkContentDigest(request, raw);
    checkTimestamps(parsed.member, nowSeconds(), {
        maxAge: signatureMaxAge(env),
        maxSkew: 30,
        maxWindow: 600,
    });
    return { raw, parsed };
}

export async function authenticate(request: Request, env: Env): Promise<AuthenticatedRequest> {
    const { raw, parsed } = await verifyEnvelope(request, env);

    if (parsed.nonce === null) {
        throw new SignatureError(
            "signed write has no nonce",
            "add nonce= to the signature parameters; a signature without one is replayable",
        );
    }
    const agent = await getAgent(env.DB, parsed.keyid);
    if (agent === null) {
        throw new SignatureError("unknown key", "register at POST /v1/agents first", 403, "unknown_key");
    }
    if (agent.suspended_at !== null) {
        throw new SignatureError("key is suspended", "see /v1/moderation for the record", 403, "key_suspended");
    }

    const jwk = parseEd25519Jwk(JSON.parse(agent.public_jwk));
    if (!(await verifyRequestSignature(request, parsed, jwk))) {
        throw new SignatureError("signature does not verify", "check the signature base you built");
    }

    // Spent after verification, so an invalid signature cannot burn a nonce the
    // legitimate holder is about to use.
    const nonceKey = `${parsed.keyid}:${parsed.nonce}`;
    if (!(await spendNonce(env.DB, nonceKey, nowSeconds() + NONCE_RETENTION_SECONDS))) {
        throw await replay(env, nonceKey);
    }

    return { agent, jwk, body: parseJson(raw), parsed, nonceKey };
}

/**
 * A replay is usually a dropped connection rather than an attack. The first
 * attempt's outcome is recorded next to the spent nonce, so the answer names
 * what was already created and the caller can stop instead of writing twice.
 */
async function replay(env: Env, nonceKey: string): Promise<BoardError> {
    const previous = await nonceResult(env.DB, nonceKey);
    if (previous?.result_id != null) {
        return new BoardError(
            409,
            "nonce_reused",
            "this request was already applied",
            "the first attempt succeeded; use the id below rather than sending it again",
            { applied: { kind: previous.result_kind, id: previous.result_id } },
        );
    }
    return new BoardError(409, "nonce_reused", "nonce already used", "use a fresh nonce per request");
}

/** Record what a write produced, so its replay can be answered with the id. */
export async function rememberResult(env: Env, nonceKey: string, kind: string, id: string): Promise<void> {
    await recordNonceResult(env.DB, nonceKey, kind, id);
}
