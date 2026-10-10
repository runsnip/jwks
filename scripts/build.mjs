/* Builds dist/: tsc compiles src/ to ES modules with their declarations. No minification: the code is short, public,
   and read by whoever audits what checks their tokens. */
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const root = new URL("..", import.meta.url).pathname;
fs.rmSync(`${root}dist`, { recursive: true, force: true });
const tsc = `${root}node_modules/typescript/bin/tsc`;
execFileSync(process.execPath, [tsc, "-p", `${root}tsconfig.json`], { stdio: "inherit" });
const files = fs.readdirSync(`${root}dist`);
console.log(`dist/: ${files.length} files`);
