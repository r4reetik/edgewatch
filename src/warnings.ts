// node:sqlite prints an ExperimentalWarning on Node 22; it is stable enough for this use.
// Imported first by every entry point, before node:sqlite loads.

const emitWarning = process.emitWarning.bind(process);
process.emitWarning = ((warning: string | Error, ...rest: unknown[]) => {
  if (String((warning as Error)?.message ?? warning).includes("SQLite")) return;
  (emitWarning as (...a: unknown[]) => void)(warning, ...rest);
}) as typeof process.emitWarning;
