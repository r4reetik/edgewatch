// Shorthands for check tests: run the engine on an inventory and pick results.

import { evaluate } from "../../src/core/engine.ts";
import type { EngineOptions, Inventory, Result } from "../../src/core/types.ts";
import { opts } from "../fixtures/inventory.ts";

/** Failing results from Keelson's own checks (Security Center insights left out). */
export const failing = (inv: Inventory, o: EngineOptions = opts()): Result[] => evaluate(inv, o).findings.filter((f) => f.source === "custom");
/** IDs of the checks that fail. */
export const failIds = (inv: Inventory, o: EngineOptions = opts()): Set<string> => new Set(failing(inv, o).map((f) => f.checkId));
/** Failing results of one check. */
export const failuresOf = (inv: Inventory, id: string, o: EngineOptions = opts()): Result[] => failing(inv, o).filter((f) => f.checkId === id);
/** Every evaluation of one check, passing and failing. */
export const evaluated = (inv: Inventory, id: string, o: EngineOptions = opts()): Result[] => evaluate(inv, o).results.filter((r) => r.checkId === id);
