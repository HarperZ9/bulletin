/** Board-wide counts. One query, used by the face and by `/v1/stats`. */

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
