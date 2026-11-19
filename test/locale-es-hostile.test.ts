// Hostile-pass regressions for #122 (FIL-6): Spanish read-backs, texts and disclosures.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { normaliseFieldValue, validateForm } from "../src/file/intake.ts";
import { applyFindings, findCardNumbers } from "../src/core/redaction.ts";
import { formatAmount } from "../src/pay/paylink.ts";
import { ACCOUNT, DOB, form, rejects, setup, testConfig, wording } from "./helpers.ts";

const PAN = "4111111111111111";
const ES = ["cero", "uno", "dos", "tres", "cuatro", "cinco", "seis", "siete", "ocho", "nueve"];

describe("hostile #122: a Spanish call and words it has no Spanish for", () => {
  it("never records a consent to a wording with no Spanish text, and never attaches a flow that would ask for one", async () => {
    const t = setup({
      config: testConfig((c) => {
        c.flows = { consent: { steps: [{ type: "trace.consent", purpose: "texts" }] } };
      }),
    });
    const { callId } = await t.engine.startCall({ locale: "es" });
    await assert.rejects(t.engine.recordConsent(callId, { purpose: "texts", answer: "yes" }), rejects("precondition_failed", /no es text/));
    await assert.rejects(t.engine.startCall({ locale: "es", flow: "consent" }), rejects("precondition_failed", /no es text/));
    assert.equal((await t.ledger.list()).some((e) => e.event === "consent.recorded"), false);
  });

  it("never opens a form that has a field with no Spanish label", async () => {
    const t = setup({
      config: testConfig((c) => {
        const f = structuredClone(form) as typeof form & { fields: Array<{ label: Record<string, string> }> };
        f.fields[0]!.label.es = "Problema";
        (c.modules.dossier!.settings as { forms: unknown[] }).forms = [f];
      }),
    });
    const { callId } = await t.engine.startCall({ locale: "es" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await assert.rejects(t.engine.startIntake(callId, "repair"), rejects("precondition_failed", /no es label/));
  });

  it("refuses a locale it does not have, whatever its shape", async () => {
    const t = setup();
    for (const locale of ["ES", "es-MX", "pt", "", "__proto__", "constructor", 1, ["es"]]) {
      await assert.rejects(t.engine.startCall({ locale } as never), rejects("invalid_input", /locale/), String(locale));
    }
    assert.equal((await t.engine.startCall({ locale: "es" })).callId.length > 0, true);
    // null is taken as absent, as undefined is: the default locale, never an unchecked one.
    const { callId } = await t.engine.startCall({ locale: null } as never);
    assert.equal(((await t.sessions.get("ws_test", callId))!.record as { locale: string }).locale, "en");
  });

  it("refuses a Spanish label or text that is empty, null or not a string, and an unknown locale key", () => {
    for (const es of ["", "   ", null, 5]) {
      assert.throws(() => setup({ config: testConfig((c) => ((c.modules.trace!.settings as { wordings: Array<{ text: Record<string, unknown> }> }).wordings[0]!.text.es = es)) }), /es/, String(es));
    }
    assert.throws(() => setup({ config: testConfig((c) => ((c.modules.trace!.settings as { wordings: Array<{ text: Record<string, unknown> }> }).wordings[0]!.text.pt = "Hola")) }), /not a locale/);
    void wording;
  });
});

describe("hostile #122: Spanish card numbers", () => {
  it("redacts a card number read digit by digit in Spanish, mixed with English and French", () => {
    const spoken = Array.from(PAN, (d) => ES[Number(d)]).join(" ");
    assert.equal(applyFindings(spoken, findCardNumbers(spoken)), "[card number removed]");
    const mixed = `cuatro one un uno ${Array.from(PAN.slice(4), (d) => ES[Number(d)]).join(" ")}`;
    assert.equal(applyFindings(mixed, findCardNumbers(mixed)), "[card number removed]");
    const upper = Array.from(PAN, (d) => ES[Number(d)]!.toUpperCase()).join("-");
    assert.equal(applyFindings(upper, findCardNumbers(upper)), "[card number removed]");
  });

  it("formats Spanish amounts in its region's currency style", () => {
    assert.match(formatAmount("es", 150050, "usd"), /1,500\.50/);
    assert.match(formatAmount("es", 150, "jpy"), /150/);
  });
});

describe("hostile #122: Spanish names for a social security number", () => {
  const refused = (key: string, label: string) =>
    validateForm({ formId: "f", version: "1", fields: [{ key, label: { en: "Number", fr: "Numéro", es: label }, type: "text", required: false }] }).some((e) => /names a card/.test(e));

  it("refuses NSS and its full names, as a word, run together, or in a label", () => {
    for (const [key, label] of [
      ["nss", "Número"],
      ["nss_number", "Número"],
      ["nssNumero", "Número"],
      ["numero", "NSS"],
      ["numero", "N.S.S."],
      ["numero", "Número de seguridad social"],
      ["numero", "número de seguro social"],
      ["numerotarjeta", "Número"],
    ] as const) {
      assert.equal(refused(key, label), true, `${key} / ${label}`);
    }
  });

  it("still takes words that only hold the letters", () => {
    for (const [key, label] of [["business", "Negocio"], ["vinos", "Vinos"], ["seguridad", "Seguridad del edificio"]] as const) {
      assert.equal(refused(key, label), false, `${key} / ${label}`);
    }
  });
});

describe("hostile #122: Spanish spoken answers are refused until a reviewed vocabulary exists", () => {
  it("never takes sí or si as a spoken yes, and keeps the English words", () => {
    const field = { key: "urgent", label: { en: "Urgent", fr: "Urgent", es: "Urgente" }, type: "yes_no" as const, required: false };
    for (const word of ["sí", "si", "Sí", "SÍ", "sí"]) assert.deepEqual(normaliseFieldValue(field, word), { ok: false, reason: "not_yes_or_no" }, word);
    assert.deepEqual(normaliseFieldValue(field, "yes"), { ok: true, value: true });
    assert.deepEqual(normaliseFieldValue(field, "no"), { ok: true, value: false });
  });

  it("asks a Spanish caller to confirm on the keypad, and refuses a voice confirmation on a Spanish call", async () => {
    const t = setup({
      config: testConfig((c) => {
        const f = structuredClone(form) as typeof form & { fields: Array<{ label: Record<string, string> }> };
        for (const field of f.fields) field.label.es = field.key;
        (c.modules.dossier!.settings as { forms: unknown[] }).forms = [f];
      }),
    });
    const { callId } = await t.engine.startCall({ locale: "es" });
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    await t.engine.setIntakeField(callId, "issue", "Fuga");
    const readBack = await t.engine.intakeReadBack(callId);
    assert.equal(readBack.prompt, "¿Es correcto? Oprima el 1 para confirmar.");
    await assert.rejects(t.engine.confirmIntake(callId, { confirmedBy: "voice", readBack: readBack.digest }), rejects("precondition_failed", /keypad/));
    assert.equal((await t.engine.confirmIntake(callId, { confirmedBy: "keypad", readBack: readBack.digest })).confirmedBy, "keypad");
  });
});
