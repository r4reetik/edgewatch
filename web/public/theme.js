// Applies the saved or system color mode before first paint (an external file, so the CSP needs no inline scripts).
(function () {
  var mode = null;
  // "edgewatch-mode" is the key from before the rename to Keelson.
  try { mode = localStorage.getItem("keelson-mode") || localStorage.getItem("edgewatch-mode"); } catch (e) {}
  if (mode !== "light" && mode !== "dark") mode = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.setAttribute("data-mode", mode);
})();
