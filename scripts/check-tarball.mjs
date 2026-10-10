/* What npm would publish: dist (every module and its declaration), README, LICENSE, package.json; no source, test,
   bench or script. */
import { execFileSync } from "node:child_process";

const [pack] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { encoding: "utf8" }));
const files = pack.files.map((f) => f.path).sort();
const wrong = [];
for (const f of files) if (!/^(dist\/[a-z-]+\.(js|d\.ts)|README\.md|LICENSE|package\.json)$/.test(f)) wrong.push(`unexpected ${f}`);
for (const name of ["index", "errors", "jwk", "jwks", "oauth", "verify"]) for (const ext of ["js", "d.ts"]) if (!files.includes(`dist/${name}.${ext}`)) wrong.push(`missing dist/${name}.${ext}`);
if (wrong.length) { console.error(wrong.join("\n")); process.exit(1); }
console.log(`${files.length} files, ${pack.size} bytes packed`);
