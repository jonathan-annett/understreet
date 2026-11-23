#!/usr/bin/env node
// Ask the Cloudflare Angel's token desk for a deploy token, and collect it. No dependencies.
//
//   node angel-token.mjs request --worker NAME [--worker NAME ...] --hours N --task "TEXT" --why "TEXT"
//   node angel-token.mjs collect     wait for the answer to the request already filed
//   node angel-token.mjs status      how long the current token has left
//
// Reads .angel-desk.json (placed by Jonathan: desk URL, your agent name, your enrolment secret).
// On success it rewrites the five CLOUDFLARE_* / ANGEL_TOKEN_* lines in .env and keeps every other line.
// It never prints a token or a secret. Jonathan must approve each request, usually within 5 minutes
// of the Angel raising it; "expired" means nobody answered, so ask again later, never for more.
import { createDecipheriv, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const DESK = ".angel-desk.json", PENDING = ".angel-desk-pending.json", ENV = ".env";
const KEYS = ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "ANGEL_TOKEN_NAME", "ANGEL_TOKEN_WORKER", "ANGEL_TOKEN_EXPIRES"];
const die = (message) => { console.error(message); process.exit(1); };
const sleep = (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000));

function envLine(name) {
  if (!existsSync(ENV)) return null;
  const line = readFileSync(ENV, "utf8").split("\n").find((l) => l.startsWith(name + "="));
  return line ? line.slice(name.length + 1) : null;
}

function mustBeIgnored() {
  for (const file of [DESK, PENDING, ENV]) {
    try { execFileSync("git", ["check-ignore", "-q", file], { stdio: "ignore" }); }
    catch { die(`${file} is not git-ignored here. Add it to .gitignore first.`); }
  }
}

function desk() {
  if (!existsSync(DESK)) die(`${DESK} is missing. Jonathan places it; ask him.`);
  const { url, agent, secret } = JSON.parse(readFileSync(DESK, "utf8"));
  return async (method, path, body) => {
    const response = await fetch(url + path, {
      method, body: body ? JSON.stringify(body) : undefined,
      headers: { authorization: `Bearer ${agent}.${secret}`, "content-type": "application/json" },
    });
    const data = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
    if (!response.ok) die(`The desk said no (${response.status}): ${data.error}`);
    return data;
  };
}

function open(sealed, privateJwk, requestId) {
  const [version, ephemeral, nonce, body] = sealed.split(".");
  if (version !== "v1") die("Unknown sealed format.");
  const [ephemeralRaw, bytes] = [Buffer.from(ephemeral, "base64url"), Buffer.from(body, "base64url")];
  const privateKey = createPrivateKey({ key: privateJwk, format: "jwk" });
  const shared = diffieHellman({ privateKey,
    publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: ephemeral }, format: "jwk" }) });
  const mine = Buffer.from(privateJwk.x, "base64url");
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeralRaw, mine]), "angel-desk-v1", 32));
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(nonce, "base64url"));
  decipher.setAAD(Buffer.from(requestId, "utf8"));
  decipher.setAuthTag(bytes.subarray(bytes.length - 16));
  return Buffer.concat([decipher.update(bytes.subarray(0, bytes.length - 16)), decipher.final()]).toString("utf8");
}

function writeEnv(text) {
  const fresh = text.split("\n").filter((l) => KEYS.some((k) => l.startsWith(k + "=")));
  if (fresh.length !== KEYS.length) die("The delivered token file was not in the expected form; .env left alone.");
  const kept = existsSync(ENV) ? readFileSync(ENV, "utf8").split("\n").filter((l) => l && !KEYS.some((k) => l.startsWith(k + "="))) : [];
  writeFileSync(ENV, [...fresh, ...kept].join("\n") + "\n", { mode: 0o600 });
  chmodSync(ENV, 0o600);
}

async function collect() {
  if (!existsSync(PENDING)) die("No request is waiting. File one with: request");
  const pending = JSON.parse(readFileSync(PENDING, "utf8"));
  const call = desk();
  let wait = 15, waited = 0;
  for (;;) {
    const r = await call("GET", `/requests/${pending.id}`);
    if (r.status === "issued") {
      writeEnv(open(r.ciphertext, pending.key, pending.id));
      rmSync(PENDING);
      console.log(`Token issued for ${r.workers.join(", ")}; expires ${r.expires}.${r.countered ? " It is narrower than you asked for." : ""}`);
      if (r.reasoning) console.log(`The Angel's note: ${r.reasoning}`);
      return;
    }
    if (r.status === "refused" || r.status === "expired") {
      rmSync(PENDING);
      die(`Request ${r.status}. ${r.reasoning || ""}\nDo not ask again for more; tell Jonathan.`);
    }
    if (waited >= 1800) die(`Still ${r.status} after 30 minutes. Carry on with other work and run: collect`);
    console.log(`${r.status}${r.broker_offline ? " (the Angel is offline; Jonathan needs to start it)" : ""}; checking again in ${wait} s`);
    await sleep(wait);
    waited += wait;
    // Jonathan answers within about five minutes of the Angel raising it, so check often once it is raised.
    wait = r.status === "pending" ? Math.min(wait * 2, 240) : 10;
  }
}

async function request(argv) {
  const args = { worker: [] };
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i].replace(/^--/, "");
    if (!["worker", "hours", "task", "why"].includes(name) || argv[i + 1] === undefined) die(`Unknown or incomplete option ${argv[i]}`);
    if (name === "worker") args.worker.push(argv[i + 1]); else args[name] = argv[i + 1];
  }
  if (!args.worker.length || !args.hours || !args.task || !args.why) die("Needed: --worker, --hours, --task, --why");
  if (existsSync(PENDING)) die("A request is already waiting. Run: collect");
  let repo = process.cwd();
  try { repo = execFileSync("git", ["remote", "get-url", "origin"], { encoding: "utf8" }).trim().replace(/\/\/[^@/]*@/, "//"); } catch {}
  const pair = generateKeyPairSync("x25519");
  const key = pair.privateKey.export({ format: "jwk" });
  const filed = await desk()("POST", "/requests", { role: "deploy", workers: args.worker, hours: Number(args.hours),
    task: args.task, why: args.why, repo, pubkey: Buffer.from(key.x, "base64url").toString("base64") });
  writeFileSync(PENDING, JSON.stringify({ id: filed.id, key }), { mode: 0o600 });
  console.log(`Request ${filed.id} filed. Jonathan has to approve it.`);
  await collect();
}

const [command, ...rest] = process.argv.slice(2);
if (command === "status") {
  const expires = envLine("ANGEL_TOKEN_EXPIRES");
  if (!expires) die("No Angel token in .env.");
  const hours = (new Date(expires) - Date.now()) / 3600000;
  console.log(hours > 0 ? `Token for ${envLine("ANGEL_TOKEN_WORKER")}: ${hours.toFixed(1)} hours left (expires ${expires}).` : `Token expired at ${expires}.`);
} else if (command === "request") { mustBeIgnored(); await request(rest); }
else if (command === "collect") { mustBeIgnored(); await collect(); }
else die("Usage: node angel-token.mjs request|collect|status   (see the top of this file)");
