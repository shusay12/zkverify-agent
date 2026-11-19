const PROTOCOL_VERSION = "v1";
const SIG_HEADER = "x-agent-games-signature";
const R = { OK:"OK", MISSING_PROOF:"MISSING_PROOF", PROOF_TX_MISSING:"PROOF_TX_MISSING", VK_MISMATCH:"VK_MISMATCH", DOMAIN_MISMATCH:"DOMAIN_MISMATCH", THRESHOLD_MISMATCH:"THRESHOLD_MISMATCH", EXPIRED_CONDITION:"EXPIRED_CONDITION", BLOCK_TOO_OLD:"BLOCK_TOO_OLD", RECIPIENT_MISMATCH:"RECIPIENT_MISMATCH", AMOUNT_MISMATCH:"AMOUNT_MISMATCH", STALE_PROOF:"STALE_PROOF", MALFORMED_REQUEST:"MALFORMED_REQUEST" };
async function hmacHex(secret, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function firstPresent(obj, keys) { for (const k of keys) { if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k]; } return undefined; }
function eqLoose(a, b) { return String(a).trim().toLowerCase() === String(b).trim().toLowerCase(); }
function toBigIntOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return Number.isFinite(v) ? BigInt(Math.trunc(v)) : null;
  if (typeof v === "string") { try { return BigInt(v.trim()); } catch { return null; } }
  return null;
}
function reject(reason_code, input) { return { decision: "REJECT", reason_code, proof_tx: input?.proof_tx ?? null }; }
function judgeGatekeeper(input, ctx = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return reject(R.MALFORMED_REQUEST, input);
  const proofTx = firstPresent(input, ["proof_tx", "proofTx", "proof_reference", "proofReference"]);
  const proof = firstPresent(input, ["proof"]);
  const registeredVk = firstPresent(input, ["registered_vk", "registeredVk", "registered_vk_hash"]);
  const proofVk = firstPresent(input, ["proof_vk", "proofVk", "vkHash", "vk_hash"]);
  if ((proofTx === undefined || proofTx === null || proofTx === "") && !proof) return reject(proofTx === undefined ? R.PROOF_TX_MISSING : R.MISSING_PROOF, input);
  if (proofVk !== undefined && registeredVk !== undefined && !eqLoose(proofVk, registeredVk)) return reject(R.VK_MISMATCH, input);
  const expectedDomain = firstPresent(input, ["expected_domain", "expectedDomain", "condition_domain", "conditionDomain"]);
  const proofDomain = firstPresent(input, ["proof_domain", "proofDomain", "domainId", "domain_id"]);
  if (expectedDomain !== undefined && proofDomain !== undefined && !eqLoose(expectedDomain, proofDomain)) return reject(R.DOMAIN_MISMATCH, input);
  if (expectedDomain === undefined && input.domain !== undefined && input.domainId !== undefined && !eqLoose(input.domain, input.domainId)) return reject(R.DOMAIN_MISMATCH, input);
  const minimum = toBigIntOrNull(firstPresent(input, ["minimum", "min_balance", "threshold"]));
  const balance = toBigIntOrNull(firstPresent(input, ["public_balance", "publicBalance", "balance"]));
  if (minimum !== null && balance !== null && balance < minimum) return reject(R.THRESHOLD_MISMATCH, input);
  const expiryBlock = toBigIntOrNull(firstPresent(input, ["expiry_block", "expiryBlock"]));
  const currentBlock = toBigIntOrNull(firstPresent(input, ["current_block", "currentBlock", "current_block_number"]));
  if (expiryBlock !== null && currentBlock !== null && currentBlock > expiryBlock) return reject(R.EXPIRED_CONDITION, input);
  const proofBlock = toBigIntOrNull(firstPresent(input, ["blockNumber", "block_number", "proof_block"]));
  const maxAge = toBigIntOrNull(firstPresent(input, ["max_block_age", "maxAgeBlocks", "max_age_blocks"]));
  if (expiryBlock === null && proofBlock !== null && currentBlock !== null && maxAge !== null) { if (currentBlock - proofBlock > maxAge) return reject(R.BLOCK_TOO_OLD, input); }
  const recipient = firstPresent(input, ["recipient"]);
  const conditionRecipient = firstPresent(input, ["condition_recipient", "conditionRecipient", "expected_recipient", "expectedRecipient"]);
  if (recipient !== undefined && conditionRecipient !== undefined && !eqLoose(recipient, conditionRecipient)) return reject(R.RECIPIENT_MISMATCH, input);
  const amount = toBigIntOrNull(firstPresent(input, ["amount"]));
  const maxTransfer = toBigIntOrNull(firstPresent(input, ["max_transfer", "maxTransfer", "cap"]));
  if (amount !== null && maxTransfer !== null && amount > maxTransfer) return reject(R.AMOUNT_MISMATCH, input);
  if (proofTx && typeof ctx.seenBy === "function") { const firstTask = ctx.seenBy(proofTx); if (firstTask && firstTask !== ctx.taskId) return reject(R.STALE_PROOF, input); }
  const essentialsPresent = registeredVk !== undefined && minimum !== null && balance !== null && recipient !== undefined && conditionRecipient !== undefined && amount !== null && maxTransfer !== null && expiryBlock !== null && currentBlock !== null;
  if (!essentialsPresent) return reject(R.MALFORMED_REQUEST, input);
  return { decision: "APPROVE", reason_code: R.OK, proof_tx: proofTx ?? null };
}
const seenMem = new Map();
const idemMem = new Map();
async function respond(env, status, bodyString) {
  const headers = { "content-type": "application/json" };
  const secret = env.AGENT_GAMES_SECRET || "";
  if (secret) headers[SIG_HEADER] = await hmacHex(secret, bodyString);
  return new Response(bodyString, { status, headers });
}
const respondObj = (env, status, obj) => respond(env, status, JSON.stringify(obj));
function isPreflight(body) {
  if (!body || typeof body !== "object") return true;
  const type = typeof body.type === "string" ? body.type.toLowerCase() : "";
  if (type.includes("preflight")) return true;
  if (!body.task_id && !body.input) return true;
  return false;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const secret = env.AGENT_GAMES_SECRET || "";
    const devMode = !secret;
    if (request.method === "GET" && url.pathname === "/health") return respondObj(env, 200, { status: "ok", protocolVersion: PROTOCOL_VERSION });
    if (request.method === "GET" && url.pathname === "/") return respondObj(env, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    if (request.method !== "POST" || (url.pathname !== "/agent" && url.pathname !== "/")) return respondObj(env, 404, { error: "not_found" });
    const rawText = await request.text();
    if (!devMode) {
      const expected = await hmacHex(secret, rawText);
      const given = request.headers.get(SIG_HEADER) || "";
      if (!timingSafeEqualHex(expected, given.toLowerCase())) return respondObj(env, 401, { error: "invalid_signature" });
    }
    let body;
    try { body = rawText ? JSON.parse(rawText) : {}; } catch { return respondObj(env, 400, { error: "invalid_json" }); }
    if (isPreflight(body)) return respondObj(env, 200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    const taskId = body.task_id ?? null;
    if (taskId && idemMem.has(taskId)) return respond(env, 200, idemMem.get(taskId));
    const input = body.input ?? null;
    const verdict = judgeGatekeeper(input, { taskId, seenBy: (tx) => seenMem.get(tx) || null });
    const bodyString = JSON.stringify(verdict);
    const proofTx = input?.proof_tx ?? input?.proofTx ?? null;
    if (proofTx && !seenMem.has(proofTx)) seenMem.set(proofTx, taskId);
    if (taskId) idemMem.set(taskId, bodyString);
    return respond(env, 200, bodyString);
  },
};
