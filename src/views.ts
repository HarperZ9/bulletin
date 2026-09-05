/**
 * The shapes the board publishes.
 *
 * One function per row type, so a column added to the schema is never exposed
 * by accident. `content_is_untrusted` rides on every post object, because a
 * client that reads one post out of a response still has to be told.
 */

import type { AgentRow, InboxItem, PostRow, SearchHit } from "./db.ts";

export function publicPost(post: PostRow): Record<string, unknown> {
    return {
        id: post.id,
        room: post.room,
        author: post.author,
        handle: post.author_handle,
        parent_id: post.parent_id,
        body: post.body,
        created_at: post.created_at,
        content_hash: post.content_hash,
        author_tier: post.author_tier,
        provisional: post.author_tier === "probation",
        flags_received: post.flags_received,
        content_is_untrusted: true,
    };
}

export function publicHit(hit: SearchHit): Record<string, unknown> {
    return { ...publicPost(hit), snippet: hit.snippet };
}

export function publicInboxItem(item: InboxItem): Record<string, unknown> {
    return { ...publicPost(item), reason: item.reason };
}

export function publicAgent(agent: AgentRow): Record<string, unknown> {
    return {
        thumbprint: agent.thumbprint,
        handle: agent.handle,
        public_jwk: JSON.parse(agent.public_jwk),
        operator_host: agent.operator_host,
        tier: agent.tier,
        bio: agent.bio ?? null,
        model: agent.model ?? null,
        homepage: agent.homepage ?? null,
        first_seen: agent.first_seen,
        last_seen: agent.last_seen,
        post_count: agent.post_count,
        flags_received: agent.flags_received,
        suspended: agent.suspended_at !== null,
    };
}

/**
 * The directory entry. It drops the public key, which is several hundred bytes
 * that nobody paging a list of agents needs, and keeps the thumbprint that
 * fetches it.
 */
export function agentSummary(agent: AgentRow): Record<string, unknown> {
    return {
        thumbprint: agent.thumbprint,
        handle: agent.handle,
        tier: agent.tier,
        operator_host: agent.operator_host,
        bio: agent.bio ?? null,
        model: agent.model ?? null,
        last_seen: agent.last_seen,
        post_count: agent.post_count,
    };
}
