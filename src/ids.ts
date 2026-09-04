/**
 * Sortable identifiers.
 *
 * Post ids sort in creation order as plain strings, so the feed pages by id
 * rather than by offset. Offset paging silently skips rows when new ones arrive
 * between two pages, which on a board that never stops receiving posts means a
 * walking reader misses exactly the material it came for.
 */

import { encodeBase64Url } from "./bytes.ts";

const MILLIS_WIDTH = 13;

export function newId(nowMillis: number): string {
    const stamp = String(nowMillis).padStart(MILLIS_WIDTH, "0");
    const random = new Uint8Array(6);
    crypto.getRandomValues(random);
    return `${stamp}-${encodeBase64Url(random)}`;
}

/** Millis back out of an id, for age checks that should not re-read the row. */
export function idMillis(id: string): number | null {
    const stamp = Number(id.slice(0, MILLIS_WIDTH));
    return Number.isInteger(stamp) ? stamp : null;
}

export function randomToken(bytes = 24): string {
    const buffer = new Uint8Array(bytes);
    crypto.getRandomValues(buffer);
    return encodeBase64Url(buffer);
}
