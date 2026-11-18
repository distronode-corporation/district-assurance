// The demo page: pick a flow, run its scripted steps one request at a time, and show what the
// server answers. Every value is written with textContent, never as markup. The receipt and the
// ledger hashes are checked here, in the browser, by receipt-check.js.
import { checkReceipt, entryHashMatches, shortHash, tamperedCopy } from "./receipt-check.js";

/** @param {string} id */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));

const REASONS = {
  valid: "valid",
  wrong_alg: "not ES256",
  unknown_kid: "signed by a key that is not in the key set",
  bad_key: "the key in the key set does not load",
  malformed_signature: "the signature is not 64 bytes of base64url",
  signature_mismatch: "the signature does not match the body",
};

/** @type {null | { runId: string, steps: string[], next: number, done: boolean, callId: string | null }} */
let current = null;
let busy = false;

/**
 * @param {string} path
 * @param {RequestInit} [init]
 */
async function api(path, init) {
  const res = await fetch(path, init);
  const body = await res.json();
  if (!res.ok) throw new Error(typeof body.error === "string" ? body.error : `HTTP ${res.status}`);
  return body;
}

/**
 * @param {string} path
 * @param {unknown} body
 */
const post = (path, body) => api(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

/** @param {string} text */
function announce(text) {
  const region = $("announce");
  region.textContent = "";
  // A fresh node each time, so a repeated message is still read out.
  window.setTimeout(() => {
    region.textContent = text;
  }, 50);
}

/**
 * @param {string} tag
 * @param {string} [text]
 * @param {string} [className]
 */
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className !== undefined) node.className = className;
  return node;
}

/**
 * While a request runs, the buttons say so with aria-disabled and ignore clicks, but keep focus:
 * a disabled button would drop keyboard focus to the page. Once a run is done its step buttons
 * are disabled for real.
 *
 * @param {boolean} value
 */
function setBusy(value) {
  busy = value;
  const finished = current === null || current.done;
  for (const id of ["next", "rest", "start"]) {
    const button = /** @type {HTMLButtonElement} */ ($(id));
    button.setAttribute("aria-disabled", String(value));
    if (id !== "start") button.disabled = finished;
  }
  $("run").setAttribute("aria-busy", String(value));
}

async function loadFlows() {
  const { flows } = await api("/demo/flows");
  const box = $("flows");
  box.replaceChildren();
  flows.forEach((flow, i) => {
    const id = `flow-${flow.flow}`;
    const row = el("div", undefined, "choice");
    const input = /** @type {HTMLInputElement} */ (el("input"));
    Object.assign(input, { type: "radio", name: "flow", id, value: flow.flow, checked: i === 0 });
    input.setAttribute("aria-describedby", `${id}-summary`);
    const label = el("label");
    label.htmlFor = id;
    label.append(el("code", flow.flow), el("span", ` (${flow.steps.length} steps)`, "muted"));
    const summary = el("p", flow.summary, "muted");
    summary.id = `${id}-summary`;
    row.append(input, label, summary);
    box.append(row);
  });
}

function renderSteps(view) {
  const list = $("steps");
  list.replaceChildren();
  view.steps.forEach((label, i) => {
    const item = el("li");
    const result = view.results[i];
    let status = "to do";
    if (result !== undefined) status = result.ok ? "done" : "check failed";
    else if (i === view.next && !view.done) status = "next";
    item.className = `step ${status.replace(" ", "-")}`;
    if (status === "next") item.setAttribute("aria-current", "step");
    item.append(el("span", status, "badge"), el("span", label, "label"));
    if (result !== undefined) item.append(el("span", result.detail, "detail"));
    list.append(item);
  });
}

function renderState(view) {
  const facts = $("state");
  facts.replaceChildren();
  const s = view.state;
  const rows = s === null
    ? [["Call", "not started yet"]]
    : [
        ["Call", s.callId],
        ["Phase", s.phase],
        ["Level", String(s.level)],
        ["Factors", s.factors.length === 0 ? "none" : s.factors.map((f) => `${f.kind}: ${f.passed ? "passed" : "failed"}`).join(", ")],
        ["Grant", s.grant === null ? "none" : `level ${s.grant.level}: ${s.grant.scopes.join(", ")}`],
        ["Sensitive", s.sensitive ?? "no"],
        ["Records", s.recordIds.join(", ") || "none"],
        ["Payments", s.paymentIds.join(", ") || "none"],
        ["Flow", view.position === null ? "none" : `${view.position.flow}: ${view.position.status}, step ${view.position.index}`],
        ["Ended", s.endedAt === null ? "no" : "yes"],
      ];
  for (const [term, value] of rows) facts.append(el("dt", term), el("dd", value));
  $("state-json").textContent = JSON.stringify(s, null, 2);
}

async function renderLedger(view) {
  $("chain").textContent = view.chain.ok
    ? `The server checked the whole ledger (${view.chain.entries} entries, every run's calls): hash chain intact.`
    : "The server found the ledger's hash chain BROKEN.";
  const body = $("ledger");
  body.replaceChildren();
  const checks = [];
  for (const entry of view.ledger) {
    const row = el("tr");
    const hash = el("td");
    hash.append(el("code", shortHash(entry.hash)));
    hash.title = entry.hash;
    const check = el("td", "checking...");
    row.append(el("td", String(entry.seq)), el("td", entry.event), el("td", entry.actor), el("td", JSON.stringify(entry.detail), "json"), hash, check);
    body.append(row);
    checks.push(entryHashMatches(entry).then((ok) => {
      check.textContent = ok ? "matches" : "MISMATCH";
      check.className = ok ? "ok" : "bad";
    }));
  }
  if (view.ledger.length === 0) {
    const row = el("tr");
    const cell = el("td", "No entries for this call yet.", "muted");
    cell.colSpan = 6;
    row.append(cell);
    body.append(row);
  }
  await Promise.all(checks);
}

function resetReceipt() {
  $("receipt-status").textContent = "The receipt is signed when the call ends.";
  for (const id of ["receipt-retry", "receipt-check", "tamper", "tamper-result", "receipt-details"]) $(id).hidden = true;
}

/** @param {{ ok: boolean, reason: keyof typeof REASONS }} result */
function verdict(node, result, kid) {
  node.hidden = false;
  node.className = `verdict ${result.ok ? "ok" : "bad"}`;
  node.textContent = result.ok
    ? `Signature valid: ES256 over the canonical body, checked in this browser against key ${kid} from /.well-known/receipt-keys.json.`
    : `Signature rejected: ${REASONS[result.reason]}.`;
}

let lastReceipt = null;
let lastKeys = [];

async function showReceipt(callId) {
  const res = await fetch(`/receipts/${encodeURIComponent(callId)}`);
  if (res.status === 404) {
    $("receipt-status").textContent = "This flow has no trace.receipt step, so the call has no receipt: the ledger holds it all.";
    return "This flow issues no receipt.";
  }
  if (!res.ok) throw new Error(`receipt: HTTP ${res.status}`);
  const receipt = await res.json();
  const { keys } = await api("/.well-known/receipt-keys.json");
  lastReceipt = receipt;
  lastKeys = keys;
  const result = await checkReceipt(receipt, keys);
  $("receipt-status").textContent = `Receipt ${receipt.body.receiptId} for ${receipt.body.callId}, fetched from /receipts/${receipt.body.callId}.`;
  verdict($("receipt-check"), result, receipt.kid);
  $("tamper").hidden = false;
  $("tamper-result").hidden = true;
  $("receipt-json").textContent = JSON.stringify(receipt, null, 2);
  $("receipt-details").hidden = false;
  return result.ok ? "Receipt signature valid." : `Receipt signature rejected: ${REASONS[result.reason]}.`;
}

/**
 * Fetches and checks the receipt; on a failure, offers a retry that runs no engine step.
 *
 * @param {string} callId
 * @returns {Promise<string>} what to announce
 */
async function loadReceipt(callId) {
  try {
    const message = await showReceipt(callId);
    $("receipt-retry").hidden = true;
    return message;
  } catch (error) {
    $("receipt-status").textContent = `Could not fetch or check the receipt: ${error instanceof Error ? error.message : String(error)}.`;
    $("receipt-retry").hidden = false;
    return "Could not fetch the receipt; the receipt section has a button to try again.";
  }
}

async function render(view) {
  current = view;
  $("run").hidden = false;
  $("panels").hidden = false;
  $("run-summary").textContent = `${view.flow}: ${view.summary}`;
  renderSteps(view);
  renderState(view);
  await renderLedger(view);
}

/**
 * After a failed step request, reads the run back: the step may have run with its answer lost.
 * A finished run then shows as finished, with its receipt.
 *
 * @returns {Promise<string>} what to add to the announcement
 */
async function recover() {
  if (current === null) return "";
  try {
    const view = await api(`/demo/runs/${current.runId}`);
    await render(view);
    if (view.done && view.callId !== null) return `The run is finished. ${await loadReceipt(view.callId)}`;
    return `The run is at step ${view.next + 1} of ${view.steps.length}.`;
  } catch (error) {
    return `The run could not be read back (${error instanceof Error ? error.message : String(error)}): start a new run.`;
  }
}

async function step() {
  if (current === null || current.done || busy) return false;
  setBusy(true);
  try {
    const view = await post(`/demo/runs/${current.runId}/next`, {});
    await render(view);
    const result = view.results.at(-1);
    let message = `Step ${result.index + 1} of ${view.steps.length}, ${result.label}: ${result.detail}.${result.ok ? "" : " The check failed."}`;
    if (view.done && view.callId !== null) message += ` Run finished. ${await loadReceipt(view.callId)}`;
    announce(message);
    return true;
  } catch (error) {
    announce(`Something went wrong: ${error instanceof Error ? error.message : String(error)}. ${await recover()}`);
    return false;
  } finally {
    setBusy(false);
    // The step buttons are disabled once the run is done: keep focus somewhere useful.
    const focused = document.activeElement;
    if (current !== null && current.done && (focused === null || focused === document.body || (focused instanceof HTMLButtonElement && focused.disabled))) {
      $("receipt-heading").focus();
    }
  }
}

$("pick").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  const choice = /** @type {HTMLInputElement | null} */ (document.querySelector('input[name="flow"]:checked'));
  if (choice === null) {
    announce("Pick a flow first.");
    return;
  }
  setBusy(true);
  try {
    const view = await post("/demo/runs", { flow: choice.value });
    // Only once the new run exists: a failed start keeps the previous run and its receipt.
    resetReceipt();
    lastReceipt = null;
    await render(view);
    announce(`Run started: ${choice.value}, ${current.steps.length} steps. Nothing has run yet.`);
    $("run-heading").focus();
  } catch (error) {
    announce(`Something went wrong: ${error instanceof Error ? error.message : String(error)}.`);
  } finally {
    setBusy(false);
  }
});

$("next").addEventListener("click", () => {
  void step();
});

$("rest").addEventListener("click", async () => {
  while (current !== null && !current.done && (await step()));
});

$("receipt-retry").addEventListener("click", async () => {
  if (current === null || current.callId === null || busy) return;
  setBusy(true);
  try {
    announce(await loadReceipt(current.callId));
    if ($("receipt-retry").hidden) $("receipt-heading").focus();
  } finally {
    setBusy(false);
  }
});

$("tamper").addEventListener("click", async () => {
  if (lastReceipt === null || busy) return;
  const receipt = lastReceipt;
  const result = await checkReceipt(tamperedCopy(receipt), lastKeys);
  // A newer run may have started while the check ran: its receipt section is not this one's.
  if (lastReceipt !== receipt) return;
  const node = $("tamper-result");
  node.hidden = false;
  node.className = `verdict ${result.ok ? "bad" : "ok"}`;
  node.textContent = result.ok
    ? "The changed receipt was ACCEPTED: something is wrong."
    : `Changed the first character of body.ledger.hash: the signature no longer matches, so the changed receipt is rejected (${REASONS[result.reason]}).`;
  announce(node.textContent);
});

setBusy(false);
loadFlows().catch((error) => {
  $("flows").replaceChildren(el("p", `Could not load the flows: ${error instanceof Error ? error.message : String(error)}.`, "bad"));
});
