#!/usr/bin/env node
// Edgewatch was renamed Keelson in 0.10. This package only starts keelson, so
// `npx edgewatch@latest`, which older installations show as their upgrade step,
// keeps working. The release workflow publishes it with every release, at the
// same version as keelson. keelson checks the Node.js version itself.
process.stderr.write("Edgewatch is now called Keelson. Next time, start it with: npx keelson@latest\n\n");
await import("keelson/dist/bin.js");
