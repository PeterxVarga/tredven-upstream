import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const [repo, source] = process.argv.slice(2);
if (!repo) throw Error("usage: node native-baseline-check.mjs REPO [JSON_FIXTURE]");
const base = "4fa42c879fd26657aec3472dcf44f08226816df3";
const next = "0cc2f479a59acdbdd8a3e4d5c6e5c15493340b7c";
const migration = "drizzle/pg/0049_stripe_projects_provider.sql";
const snapshot = "drizzle/pg/meta/0046_snapshot.json";
const git = (...args) => execFileSync("git", ["-C", resolve(repo), ...args], {
  encoding: "utf8", timeout: 10000, maxBuffer: 1024*1024,
  env: { PATH:process.env.PATH, GIT_CONFIG_NOSYSTEM:"1",
         GIT_CONFIG_GLOBAL:"", GIT_TERMINAL_PROMPT:"0",
         GIT_OPTIONAL_LOCKS:"0", GIT_NO_LAZY_FETCH:"1" },
});
const expect = (actual, pin) => {
  if (actual.trim() !== pin) throw Error("PINNED_GIT_SOURCE_MISMATCH");
};
expect(git("rev-parse", "refs/tags/v0.1.27^{commit}"), base);
expect(git("rev-parse", "refs/tags/v0.1.31^{commit}"), next);
expect(git("rev-parse", next+":"+migration), "e0f8b57738a148e219c732cb7bd54cedeecc19d9");
expect(git("rev-parse", base+":"+snapshot), "30515f76ca7538af57185b612b29f3de2d46e1bb");
const sql = git("show", next+":"+migration);
for (const fragment of [
  'CREATE TABLE "stripe_projects_grant"',
  'CREATE TABLE "stripe_projects_resource"',
  'REFERENCES "public"."user"("id")',
  'REFERENCES "public"."organization"("id")',
]) {
  if (!sql.includes(fragment)) throw Error("MIGRATION_FORMAT_UNEXPECTED");
}
const schema = JSON.parse(source ? readFileSync(source, "utf8") : git("show", base+":"+snapshot));
if (!schema.tables || typeof schema.tables !== "object") throw Error("INVALID_SCHEMA");
const parents = ["public.user", "public.organization"];
const matched = parents.map((table) => {
  const id = schema.tables[table]?.columns?.id;
  return {table, ok:id?.name === "id" && id?.type === "text" &&
    id?.primaryKey === true && id?.notNull === true};
});
const decision = matched.every((p) => p.ok) ? "REVIEW" : "BLOCKED";
process.stdout.write(JSON.stringify({decision, matched, databaseChecked:false, sqlExecuted:false, approval:false}) + "\n");
process.exitCode = decision === "BLOCKED" ? 2 : 0;
