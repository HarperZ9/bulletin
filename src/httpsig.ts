/**
 * RFC 9421 HTTP Message Signatures, restricted to the Web Bot Auth profile.
 *
 * The board authenticates a request by checking that whoever sent it holds the
 * private half of a key it already knows. There is no shared secret, so there
 * is no secret to leak, and an intercepted request cannot be turned into an
 * ongoing impersonation the way a captured bearer token can.
 *
 * The profile is narrow on purpose. Ed25519 only, one signature per request,
 * tag="web-bot-auth" required, created and expires required, and coverage of
 * the authority required so a signature captured against one host cannot be
 * replayed against another. Anything outside the profile is rejected rather
 * than accommodated: a verifier that tries to be liberal in what it accepts is
 * a verifier with an unbounded attack surface.
 */

import { encodeBase64, sha256 } from "./bytes.ts";
import { type Ed25519Jwk, verifyEd25519 } from "./jwk.ts";

export const WEB_BOT_AUTH_TAG = "web-bot-auth";

export interface SignatureMember {
    label: string;
    covered: string[];
    params: Map<string, string | number | boolean>;
    /** The received parameter text, reused verbatim as the @signature-params value. */
    raw: string;
}

export interface SignedRequest {
    method: string;
    url: string;
    headers: Headers;
}

export class SignatureError extends Error {
    readonly status: number;
    readonly hint: string;

    constructor(message: string, hint: string, status = 401) {
        super(message);
        this.name = "SignatureError";
        this.status = status;
        this.hint = hint;
    }
}

const KEY_START = /[a-z*]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;

/**
 * Parse a structured-field dictionary whose members are inner lists of strings
 * with parameters. That is the shape Signature-Input always takes; a general
 * structured-field parser would accept shapes this code has no use for.
 */
export function parseSignatureInput(input: string): SignatureMember[] {
    const members: SignatureMember[] = [];
    let i = 0;

    const skipSpace = (): void => {
        while (i < input.length && (input[i] === " " || input[i] === "\t")) {
            i += 1;
        }
    };

    const readKey = (): string => {
        const start = i;
        if (i >= input.length || !KEY_START.test(input[i] as string)) {
            throw new SignatureError("malformed Signature-Input", "expected a dictionary key");
        }
        while (i < input.length && KEY_CHAR.test(input[i] as string)) {
            i += 1;
        }
        return input.slice(start, i);
    };

    const readQuoted = (): string => {
        if (input[i] !== '"') {
            throw new SignatureError("malformed Signature-Input", "expected a quoted string");
        }
        i += 1;
        let out = "";
        while (i < input.length) {
            const ch = input[i] as string;
            if (ch === "\\") {
                const next = input[i + 1];
                if (next !== '"' && next !== "\\") {
                    throw new SignatureError("malformed Signature-Input", "bad string escape");
                }
                out += next;
                i += 2;
                continue;
            }
            if (ch === '"') {
                i += 1;
                return out;
            }
            out += ch;
            i += 1;
        }
        throw new SignatureError("malformed Signature-Input", "unterminated string");
    };

    const readParams = (): Map<string, string | number | boolean> => {
        const params = new Map<string, string | number | boolean>();
        while (i < input.length && input[i] === ";") {
            i += 1;
            skipSpace();
            const name = readKey();
            if (input[i] !== "=") {
                // A bare parameter is a boolean true in structured fields.
                params.set(name, true);
                continue;
            }
            i += 1;
            if (input[i] === '"') {
                params.set(name, readQuoted());
                continue;
            }
            const start = i;
            while (i < input.length && /[0-9-]/.test(input[i] as string)) {
                i += 1;
            }
            if (i === start) {
                throw new SignatureError("malformed Signature-Input", `parameter ${name} has no value`);
            }
            const numeric = Number(input.slice(start, i));
            if (!Number.isInteger(numeric)) {
                throw new SignatureError("malformed Signature-Input", `parameter ${name} must be an integer`);
            }
            params.set(name, numeric);
        }
        return params;
    };

    while (i < input.length) {
        skipSpace();
        if (i >= input.length) {
            break;
        }
        const label = readKey();
        if (input[i] !== "=") {
            throw new SignatureError("malformed Signature-Input", `member ${label} has no value`);
        }
        i += 1;
        const rawStart = i;
        if (input[i] !== "(") {
            throw new SignatureError("malformed Signature-Input", "expected an inner list");
        }
        i += 1;
        const covered: string[] = [];
        for (;;) {
            skipSpace();
            if (i >= input.length) {
                throw new SignatureError("malformed Signature-Input", "unterminated inner list");
            }
            if (input[i] === ")") {
                i += 1;
                break;
            }
            covered.push(readQuoted());
            // Component parameters (";req", ";name=") are outside this profile.
            if (input[i] === ";") {
                throw new SignatureError(
                    "unsupported component parameter",
                    "this board covers plain components only",
                );
            }
        }
        const params = readParams();
        members.push({ label, covered, params, raw: input.slice(rawStart, i) });
        skipSpace();
        if (i < input.length) {
            if (input[i] !== ",") {
                throw new SignatureError("malformed Signature-Input", "expected a comma between members");
            }
            i += 1;
        }
    }

    if (members.length === 0) {
        throw new SignatureError("empty Signature-Input", "send one signature");
    }
    return members;
}

/** Parse a Signature header of the form label=:base64: and return one label's bytes. */
export function parseSignatureHeader(input: string, label: string): Uint8Array {
    for (const part of splitTopLevel(input)) {
        const eq = part.indexOf("=");
        if (eq < 0) {
            continue;
        }
        if (part.slice(0, eq).trim() !== label) {
            continue;
        }
        const value = part.slice(eq + 1).trim();
        if (!value.startsWith(":") || !value.endsWith(":") || value.length < 3) {
            throw new SignatureError("malformed Signature", "the value must be a byte sequence");
        }
        try {
            return decodeStandardBase64(value.slice(1, -1));
        } catch {
            throw new SignatureError("malformed Signature", "the byte sequence is not base64");
        }
    }
    throw new SignatureError("Signature has no entry for the signed label", `expected label ${label}`);
}

function splitTopLevel(input: string): string[] {
    const parts: string[] = [];
    let depth = 0;
    let quoted = false;
    let start = 0;
    for (let i = 0; i < input.length; i += 1) {
        const ch = input[i];
        if (quoted) {
            if (ch === "\\") {
                i += 1;
            } else if (ch === '"') {
                quoted = false;
            }
            continue;
        }
        if (ch === '"') {
            quoted = true;
        } else if (ch === "(") {
            depth += 1;
        } else if (ch === ")") {
            depth -= 1;
        } else if (ch === "," && depth === 0) {
            parts.push(input.slice(start, i));
            start = i + 1;
        }
    }
    parts.push(input.slice(start));
    return parts;
}

function decodeStandardBase64(value: string): Uint8Array {
    const binary = atob(value);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        out[i] = binary.charCodeAt(i);
    }
    return out;
}

/**
 * Build the exact bytes the signer signed. Any disagreement between this
 * function and the signer's own base construction shows up as a failed
 * signature, never as a partial acceptance.
 */
export function buildSignatureBase(request: SignedRequest, member: SignatureMember): string {
    const url = new URL(request.url);
    const lines: string[] = [];

    for (const component of member.covered) {
        lines.push(`"${component}": ${componentValue(request, url, component)}`);
    }
    lines.push(`"@signature-params": ${member.raw}`);
    return lines.join("\n");
}

function componentValue(request: SignedRequest, url: URL, component: string): string {
    switch (component) {
        case "@method":
            return request.method.toUpperCase();
        case "@target-uri":
            return url.toString();
        case "@authority":
            return url.host.toLowerCase();
        case "@scheme":
            return url.protocol.replace(/:$/, "").toLowerCase();
        case "@request-target":
            return `${url.pathname}${url.search}`;
        case "@path":
            return url.pathname;
        case "@query":
            return url.search === "" ? "?" : url.search;
        default:
            break;
    }
    if (component.startsWith("@")) {
        throw new SignatureError(
            `unsupported derived component ${component}`,
            "cover @method, @authority, @path, @query, @scheme, @target-uri or @request-target",
        );
    }
    const value = request.headers.get(component);
    if (value === null) {
        throw new SignatureError(
            `signature covers absent header ${component}`,
            "every covered header must be present on the request",
        );
    }
    return value.trim().replace(/\s*\n\s*/g, " ");
}

export interface TimestampPolicy {
    /** Seconds a created may be in the past. */
    maxAge: number;
    /** Seconds a created may be in the future, to absorb clock skew. */
    maxSkew: number;
    /** Widest window the signer may claim, so a long-lived signature is refused. */
    maxWindow: number;
}

export const DEFAULT_TIMESTAMP_POLICY: TimestampPolicy = {
    maxAge: 300,
    maxSkew: 30,
    maxWindow: 600,
};

export function checkTimestamps(
    member: SignatureMember,
    nowSeconds: number,
    policy: TimestampPolicy = DEFAULT_TIMESTAMP_POLICY,
): { created: number; expires: number } {
    const created = member.params.get("created");
    const expires = member.params.get("expires");
    if (typeof created !== "number") {
        throw new SignatureError("signature has no created", "add created= to the signature parameters");
    }
    if (typeof expires !== "number") {
        throw new SignatureError("signature has no expires", "add expires= to the signature parameters");
    }
    if (expires <= created) {
        throw new SignatureError("signature expires before it was created", "check the signer clock");
    }
    if (expires - created > policy.maxWindow) {
        throw new SignatureError(
            "signature window is too wide",
            `expires may be at most ${policy.maxWindow}s after created`,
        );
    }
    if (created > nowSeconds + policy.maxSkew) {
        throw new SignatureError("signature is from the future", "check the signer clock");
    }
    if (nowSeconds - created > policy.maxAge) {
        throw new SignatureError("signature is too old", `sign within ${policy.maxAge}s of sending`);
    }
    if (nowSeconds >= expires) {
        throw new SignatureError("signature has expired", "sign a fresh request");
    }
    return { created, expires };
}

export interface ParsedSignature {
    member: SignatureMember;
    signature: Uint8Array;
    keyid: string;
    nonce: string | null;
    signatureAgent: string | null;
}

/**
 * Pull one Web Bot Auth signature off a request and check everything that does
 * not need the key. This returns before any database lookup, so a malformed
 * request costs a parse rather than a query.
 */
export function parseRequestSignature(request: SignedRequest): ParsedSignature {
    const inputHeader = request.headers.get("signature-input");
    const signatureHeader = request.headers.get("signature");
    if (inputHeader === null || signatureHeader === null) {
        throw new SignatureError(
            "request is not signed",
            "send Signature and Signature-Input per RFC 9421 with tag=web-bot-auth",
        );
    }

    const members = parseSignatureInput(inputHeader);
    const tagged = members.filter((m) => m.params.get("tag") === WEB_BOT_AUTH_TAG);
    if (tagged.length === 0) {
        throw new SignatureError(
            "no web-bot-auth signature",
            "add tag=web-bot-auth to the signature parameters",
        );
    }
    if (tagged.length > 1) {
        throw new SignatureError("more than one web-bot-auth signature", "send exactly one");
    }
    const member = tagged[0] as SignatureMember;

    const alg = member.params.get("alg");
    if (alg !== undefined && alg !== "ed25519") {
        throw new SignatureError(`unsupported alg ${String(alg)}`, "this board verifies ed25519 only");
    }

    const keyid = member.params.get("keyid");
    if (typeof keyid !== "string" || keyid.length === 0) {
        throw new SignatureError("signature has no keyid", "set keyid to the JWK SHA-256 thumbprint");
    }

    const coversAuthority =
        member.covered.includes("@authority") || member.covered.includes("@target-uri");
    if (!coversAuthority) {
        throw new SignatureError(
            "signature does not cover the authority",
            "cover @authority or @target-uri so the signature is bound to this host",
        );
    }

    const nonceParam = member.params.get("nonce");
    const agent = request.headers.get("signature-agent");

    return {
        member,
        signature: parseSignatureHeader(signatureHeader, member.label),
        keyid,
        nonce: typeof nonceParam === "string" ? nonceParam : null,
        signatureAgent: agent === null ? null : agent.trim().replace(/^"|"$/g, ""),
    };
}

export async function verifyRequestSignature(
    request: SignedRequest,
    parsed: ParsedSignature,
    jwk: Ed25519Jwk,
): Promise<boolean> {
    const base = buildSignatureBase(request, parsed.member);
    return verifyEd25519(jwk, parsed.signature, new TextEncoder().encode(base));
}

/**
 * RFC 9530 Content-Digest. A signature that covers content-digest binds the
 * body, so the body check and the signature check are separate steps and both
 * must pass before anything is written.
 */
export async function checkContentDigest(request: SignedRequest, body: Uint8Array): Promise<void> {
    const header = request.headers.get("content-digest");
    if (header === null) {
        throw new SignatureError(
            "request has no Content-Digest",
            "send Content-Digest: sha-256=:<base64>: and cover it in the signature",
            400,
        );
    }
    const match = /sha-256=:([A-Za-z0-9+/=]+):/.exec(header);
    if (match === null) {
        throw new SignatureError("unsupported Content-Digest", "use sha-256", 400);
    }
    const expected = encodeBase64(await sha256(body));
    if (match[1] !== expected) {
        throw new SignatureError("Content-Digest does not match the body", "rehash the body you sent", 400);
    }
}
