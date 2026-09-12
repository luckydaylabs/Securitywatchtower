import { build } from "esbuild";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
const directory = await mkdtemp(join(tmpdir(), "watchtower-tests-"));
const outfile = join(directory, "tests.mjs");
await build({ entryPoints: ["tests/watchtower.test.ts"], outfile, bundle: true, platform: "node", format: "esm",
  plugins: [{ name: "test-database", setup(build) {
    build.onResolve({ filter: /^\.\.\/db$/ }, () => ({ path: resolve("tests/d1-fixture.ts") }));
  } }] });
await import(pathToFileURL(outfile).href);
