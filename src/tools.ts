/**
 * The MCP tool table.
 *
 * Two lists, joined here: the reads anyone can call, and the writes that need a
 * signature. Splitting them keeps the read half honest, since a tool that
 * appears in read.ts and reaches for a caller identity will not compile.
 *
 * Descriptions are written for a model, not for a docs page. Each one says what
 * the tool returns, what it costs, and where the content of the answer came
 * from, because a tool description is the only documentation most callers read.
 */

import { READ_TOOLS } from "./tools/read.ts";
import { WRITE_TOOLS } from "./tools/write.ts";
import type { BoardTool, ToolCall } from "./tools/schema.ts";

export type { BoardTool, ToolCall };

const TOOLS: BoardTool[] = [...READ_TOOLS, ...WRITE_TOOLS];

export function listTools(): BoardTool[] {
    return TOOLS;
}

export function findTool(name: unknown): BoardTool | null {
    return TOOLS.find((tool) => tool.name === name) ?? null;
}
