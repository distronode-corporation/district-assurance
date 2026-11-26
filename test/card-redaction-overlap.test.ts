// Regressions for two card-data leaks (0.4.2). (1) A number intake field took a whole card number
// and stored it, since only text fields ran the card check. (2) Digits just before a card number (a
// phone number, a reference) could form a false Luhn match: the finder took it, skipped past it, and
// left the rest of the real card in clear. The same flaw was in the SIN and health card finders.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import {
  REDACTION_MARKERS,
  bankAccountRedactor,
  cardNumberRedactor,
  composeRedactors,
  findCardNumbers,
  findHealthCardNumbers,
  findSocialInsuranceNumbers,
  luhnValid,
  type RedactionFinding,
} from "../src/core/redaction.ts";
import { normaliseFieldValue, validateForm, type IntakeField, type IntakeForm } from "../src/file/intake.ts";
import { ACCOUNT, DOB, setup, testConfig } from "./helpers.ts";
import type { JsonValue } from "../src/index.ts";

/** Public test card numbers. */
const CARDS = ["4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "6011111111111117"];
const SIN = "046454286";
/** A 10-digit Ontario-style number that passes Luhn. */
const ONTARIO = (() => {
  for (let d = 0; d < 10; d++) if (luhnValid(`123456789${d}`)) return `123456789${d}`;
  throw new Error("none");
})();

/** Groups of four, the last one shorter when the length is not a multiple of four. */
const fours = (digits: string, sep: string) => digits.match(/.{1,4}/g)!.join(sep);

/** Whether every UTF-16 offset from start to end is inside some finding. */
function covered(findings: readonly RedactionFinding[], start: number, end: number): boolean {
  for (let at = start; at < end; at++) if (!findings.some((f) => f.start <= at && at < f.end)) return false;
  return true;
}

/** Findings sorted by position and never overlapping, as composeRedactors requires of a redactor. */
function assertOrdered(findings: readonly RedactionFinding[]): void {
  for (let k = 1; k < findings.length; k++) assert.ok(findings[k - 1]!.end <= findings[k]!.start, JSON.stringify(findings));
}

function assertCardHidden(text: string, card: string): void {
  const at = text.indexOf(card);
  assert.ok(at >= 0, `${text} holds ${card}`);
  const findings = findCardNumbers(text);
  assertOrdered(findings);
  assert.ok(covered(findings, at, at + card.length), `${JSON.stringify(text)}: ${JSON.stringify(cardNumberRedactor.redact(text).text)}`);
}

describe("card numbers after other digits (0.4.2)", () => {
  it("removes the whole card after a phone number, the reported case", () => {
    assert.equal(cardNumberRedactor.redact("416 555 0021, 4111 1111 1111 1111").text, REDACTION_MARKERS.card_number);
    assert.equal(cardNumberRedactor.redact("call me at 416 555 0021, 4111 1111 1111 1111 thanks").text, `call me at ${REDACTION_MARKERS.card_number} thanks`);
  });

  it("removes a card after any 1 to 4 digit reference, grouped by space, dash or dot", () => {
    for (const card of CARDS) {
      for (const sep of [" ", "-", "."]) {
        const written = fours(card, sep);
        for (let ref = 0; ref < 10_000; ref += ref < 1_000 ? 1 : 37) assertCardHidden(`ref ${ref}${sep}${written} ok`, written);
      }
    }
  });

  it("removes a card after a phone number, grouped by space, dash or dot", () => {
    for (const card of CARDS) {
      for (const sep of [" ", "-", "."]) {
        const written = fours(card, sep);
        for (let line = 0; line < 2_000; line++) {
          const phone = ["416", "555", String(line).padStart(4, "0")].join(sep);
          assertCardHidden(`${phone}, ${written}`, written);
          assertCardHidden(`${phone}${sep}${written}`, written);
        }
      }
    }
  });

  it("removes a card read digit by digit after a phone number read the same way", () => {
    const words = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
    const spoken = (digits: string) => [...digits].map((d) => words[Number(d)]).join(" ");
    for (let line = 0; line < 300; line++) {
      const card = spoken("4111111111111111");
      assertCardHidden(`${spoken(`416555${String(line).padStart(4, "0")}`)} ${card}`, card);
    }
  });

  it("keeps two adjacent cards two findings, and hides both after a phone number", () => {
    const two = `${fours(CARDS[0]!, " ")} ${fours(CARDS[1]!, " ")}`;
    assert.equal(cardNumberRedactor.redact(two).text, `${REDACTION_MARKERS.card_number} ${REDACTION_MARKERS.card_number}`);
    for (let line = 0; line < 2_000; line++) {
      const text = `416 555 ${String(line).padStart(4, "0")} ${two}`;
      for (const card of [fours(CARDS[0]!, " "), fours(CARDS[1]!, " ")]) assertCardHidden(text, card);
    }
  });

  it("leaves digits that hold no card as they were", () => {
    for (const text of ["416 555 0021", "416 555 0021, 1234", "order 12 34 56 78 90 12", "4111 1111 1111 1112"]) {
      assert.deepEqual(findCardNumbers(text), [], text);
    }
  });

  it("keeps the composed redactors' findings whole and ordered", () => {
    const all = composeRedactors(cardNumberRedactor, bankAccountRedactor);
    const out = all.redact("account 416 555 0021, 4111 1111 1111 1111");
    assert.equal(out.text, `account ${REDACTION_MARKERS.card_number}`);
  });
});

describe("SINs and health card numbers after other digits (0.4.2)", () => {
  it("removes a whole SIN after digits that form a false match", () => {
    const sinFound = (text: string) => findSocialInsuranceNumbers(text);
    for (const sep of [" ", "-", "."]) {
      const written = [SIN.slice(0, 3), SIN.slice(3, 6), SIN.slice(6)].join(sep);
      for (let ref = 0; ref < 1_000; ref++) {
        const three = String(ref).padStart(3, "0");
        for (const before of [three, [...three].join(" ")]) {
          const text = `${before}${sep}${written}`;
          const at = text.indexOf(written);
          const findings = sinFound(text);
          assertOrdered(findings);
          assert.ok(covered(findings, at, at + written.length), text);
        }
      }
    }
    // The case found first: 103 and the SIN's first six digits pass Luhn.
    assert.equal(findRedactor(findSocialInsuranceNumbers).redact("103 046 454 286").text, REDACTION_MARKERS.sin);
    assert.equal(findRedactor(findSocialInsuranceNumbers).redact("0 0 4 046 454 286").text, REDACTION_MARKERS.sin);
  });

  it("removes a whole Ontario health card number after digits that form a false match", () => {
    // Written in groups, the 4-3-3 breaks keep a false match out; read digit by digit, they do not.
    const grouped = [ONTARIO.slice(0, 4), ONTARIO.slice(4, 7), ONTARIO.slice(7)].join(" ");
    const singly = [...ONTARIO].join(" ");
    for (let ref = 0; ref < 10_000; ref++) for (const [written, before] of [[grouped, String(ref)], [singly, [...String(ref)].join(" ")]] as const) {
      const text = `${before} ${written}`;
      const at = text.indexOf(written);
      const findings = findHealthCardNumbers(text);
      assertOrdered(findings);
      assert.ok(covered(findings, at, at + written.length), text);
    }
  });
});

/** A redactor over one finder, for the exact-text checks. */
function findRedactor(find: (text: string) => RedactionFinding[]) {
  return {
    redact(text: string) {
      const findings = find(text);
      let out = "";
      let at = 0;
      for (const f of findings) {
        out += text.slice(at, f.start) + REDACTION_MARKERS[f.kind];
        at = f.end;
      }
      return { text: out + text.slice(at), findings };
    },
  };
}

describe("a number intake field and a card number (0.4.2)", () => {
  const units: IntakeField = { key: "units", label: { en: "Units", fr: "Unités" }, type: "number", required: false };

  it("refuses a card number as a number field's value, as a text field does", () => {
    for (const card of CARDS) {
      for (const raw of [card, ` ${card} `, `-${card}`, `${card}.0`, `${card}.25`, `0000${card}`, `-0000${card}`, `000000000${card}.000`, fours(card, " "), fours(card, "-"), fours(card, ".")]) {
        assert.deepEqual(normaliseFieldValue(units, raw), { ok: false, reason: "card_number" }, raw);
      }
    }
  });

  it("still takes ordinary numbers, a long one that is no card included", () => {
    assert.deepEqual(normaliseFieldValue(units, "42"), { ok: true, value: 42 });
    assert.deepEqual(normaliseFieldValue(units, "-2.5"), { ok: true, value: -2.5 });
    assert.deepEqual(normaliseFieldValue(units, "4111111111111112"), { ok: true, value: 4111111111111112 });
    assert.deepEqual(normaliseFieldValue(units, "4111 1111"), { ok: false, reason: "not_a_number" });
  });

  it("refuses a form whose showIf waits for a card number as a number", () => {
    const form: IntakeForm = {
      formId: "x",
      version: "1",
      fields: [units, { key: "note", label: { en: "Note", fr: "Note" }, type: "text", required: false, showIf: { field: "units", equals: 4111111111111111 } }],
    };
    assert.deepEqual(
      validateForm(form).map((p) => p.code),
      ["intake.show_if_value"],
    );
    assert.deepEqual(validateForm({ ...form, fields: [units, { ...form.fields[1]!, showIf: { field: "units", equals: 4111111111111112 } }] }), []);
  });

  it("never stores a card number given to a number field on a call", async () => {
    const config = testConfig((c) => {
      c.modules.dossier = {
        settings: { forms: [{ formId: "repair", version: "1", fields: [{ key: "issue", label: { en: "Issue", fr: "Problème" }, type: "text", required: true }, units] }] } as unknown as JsonValue,
      };
    });
    const t = setup({ config });
    const { callId } = await t.engine.startCall();
    await t.engine.beginVerification(callId, { accountNumber: ACCOUNT });
    await t.engine.submitKeypad(callId, { dob: DOB });
    await t.engine.finishVerification(callId);
    await t.engine.startIntake(callId, "repair");
    for (const raw of ["4111111111111111", "4111 1111 1111 1111"]) {
      assert.deepEqual(await t.engine.setIntakeField(callId, "units", raw), { ok: false, reason: "card_number" }, raw);
    }
    assert.deepEqual(await t.engine.setIntakeField(callId, "units", "3"), { ok: true, value: 3 });
    const stored = JSON.stringify(await t.sessions.get("ws_test", callId)) + JSON.stringify(await t.ledger.list());
    assert.ok(!stored.includes("4111111111111111") && !stored.includes("4111 1111"), "no card digits in the call record or the ledger");
  });
});
