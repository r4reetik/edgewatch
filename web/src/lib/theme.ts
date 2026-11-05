import { useSyncExternalStore } from "react";

export type Mode = "light" | "dark";
const listeners = new Set<() => void>();

export function useMode(): [Mode, (m: Mode) => void] {
  const mode = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    () => (document.documentElement.getAttribute("data-mode") === "dark" ? "dark" : "light"),
  );
  const set = (m: Mode) => {
    document.documentElement.setAttribute("data-mode", m);
    try {
      localStorage.setItem("edgewatch-mode", m);
    } catch {
      /* storage unavailable */
    }
    listeners.forEach((l) => l());
  };
  return [mode, set];
}
