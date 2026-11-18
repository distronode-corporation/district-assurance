# Specification

Version 0 (pre-alpha). This document describes what the code in `src/` does today; anything
marked *planned* names its ROADMAP.md issue.

## 1. Session state machine

A session has a **phase** and, orthogonal to it, a **sensitive** flag, a **tainted** flag, the
recorded **factors**, the current **level** and an optional **grant**.

```
            verification_started                 intake_started
  +-----------+  <--------------  +------+  -------------->  +--------+
  | verifying |                   | open |                    | filing |
  +-----------+  -------------->  +------+  <--------------  +--------+
          verification_finished    |    ^   intake_confirmed, intake_abandoned
                                   |    |
                payment_requested  v    |  payment_settled
                                +--------+
                                | paying |
                                +--------+

  call_ended, from any phase but ended  ->  ended (final)
```

| Event | Allowed in | Effect |
|---|---|---|
| `verification_started {reset}` | open | phase `verifying`; factors cleared if `reset` or the session is tainted |
| `factor_recorded {factor}` | verifying | factor appended |
| `verification_finished {level, grant}` | verifying | phase `open`, level and grant set, sensitive cleared |
| `sensitive_opened {reason: keypad}` | verifying | sensitive `keypad` |
| `sensitive_closed` | verifying, paying | sensitive cleared |
| `intake_started` | open | phase `filing` |
| `intake_confirmed {recordId}` | filing | phase `open`, record id appended |
| `intake_abandoned` | filing | phase `open` |
| `payment_requested {paymentId}` | open | phase `paying`, sensitive `payment`, payment id appended |
| `payment_settled {paymentId}` | paying | phase `open`, sensitive cleared |
| `untrusted_content {source}` | any but ended | tainted (sticky), level 0, grant dropped |
| `call_ended {at}` | any but ended | phase `ended`, grant dropped, sensitive cleared |

Any other combination throws `EngineError("invalid_transition")`. `reduce` is pure; the engine is
the only caller in the package.

**Sensitive** means: the host pauses the live transcript and stored transcript, cuts audio to
speech-to-text and the model, and holds staff listen-in. The engine tracks the flag; the host
enforces it.

## 2. Factors, levels and scopes

Factor kinds: `keypad_knowledge`, `spoken_knowledge` (planned, VER-3), `text_code` (planned,
VER-2), `carrier_identity_match`, `returning_pin` (planned, VER-6), `photo_id`. Caller ID is not
a kind.

A policy lists, per level 1 to 3, sets of factor kinds; a level is reached when every kind in one
of its sets has passed. `validatePolicy` refuses:

- a level outside 1 to 3, a level defined twice, an empty set, an unknown or repeated kind;
- at level 2 or 3, a set with fewer than two different kinds;
- at level 3, a set without `photo_id`;
- a set that is `text_code` alone;
- a scope below its floor: `payment.*`, `payout.*` and `contact.*` are at least level 2.

The default policy: level 1 is keypad knowledge; level 2 is keypad plus a trusted texted code, or
keypad plus carrier identity match, or a returning PIN plus a texted code; level 3 is keypad plus
photo ID. Scopes: `status.read` 1, `intake.file` 1, `payment.request` 2, `contact.update` 3,
`payout.update` 3. Two keypad attempts per call. A texted code counts only when the carrier
answered and reported no SIM change or port in the last 72 hours.

A **grant** carries the level, the scopes at or below it, and an expiry (15 minutes by default, at
most 60). `authorize(callId, scope)` is true only for a listed scope, on a call that has not ended,
whose minimum is 0 or whose grant includes it and has not expired.

## 3. Keypad knowledge

- Subject key: `HMAC-SHA256(knowledgeKey, "subject:" + accountNumber)`, hex.
- Field digest: `HMAC-SHA256(knowledgeKey, "field:" + field + ":" + value)`, hex.
- An entry counts only if it is 1 to 32 ASCII digits.
- `submitKeypad` compares every configured field, in constant time per field, even after a
  mismatch, and records one factor: passed only if the subject exists and every field matched.
- After `maxKeypadAttemptsPerCall` judged attempts, further submissions return `locked` without
  judging.

## 4. Engine events

Each event is one ledger entry: `name`, `callId`, `actor` (`caller`, `ai`, `code`, `member`,
`system`), `at`, and a `detail` object that never carries a value the caller keyed, an answer on
file, a phone number, a link or card data.

| Event | Detail |
|---|---|
| `call.started` | `locale` |
| `verification.started` | none |
| `verification.factor` | `kind`, `passed` (and `status` for photo ID) |
| `verification.carrier_checked` | `checked`, `textCodeTrusted`, `identityMatch` |
| `identity.link_sent` | none |
| `verification.finished` | `level`, `methods`, `discounted` |
| `grant.issued` | `grantId`, `level`, `scopes`, `expiresAt` |
| `session.tainted` | `source` |
| `sensitive.opened` / `sensitive.closed` | `reason` / none |
| `intake.started` | `formId`, `version` |
| `intake.confirmed` | `recordId`, `formId`, `digest`, `confirmedBy` |
| `intake.abandoned` | none |
| `redaction.applied` | `kinds` (counts per kind) |
| `payment.link_sent` | `paymentId`, `linkId`, `amountMinor`, `currency`, `amountSource` |
| `payment.settled` | `paymentId`, `status` |
| `consent.recorded` | `consentId`, `purpose`, `wordingVersion`, `wordingDigest`, `answer`, `locale` |
| `call.ended` | none |
| `receipt.issued` | `receiptId`, `digest`, `kid` |

## 5. Audit ledger

Entry: `{seq, prevHash, callId, actor, event, at, detail, hash}`. `seq` starts at 1; the first
`prevHash` is 64 zeros; `hash` is SHA-256 over the canonical JSON of every other field.
`verifyChain(entries, from?)` reports the first entry whose `seq`, `prevHash` or `hash` is wrong.
`chainEntry` refuses a detail in which any string (other than a 64-character hex digest) contains
a card number.

## 6. Canonical JSON

Object keys sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript
`JSON.stringify` writes them. Refused: `undefined`, functions, symbols, bigints, non-finite
numbers, sparse array holes, and objects whose prototype is not `Object.prototype` or `null`.

## 7. Receipts

```json
{
  "body": {
    "v": 1, "receiptId": "...", "callId": "...", "workspaceId": "...",
    "startedAt": "...", "endedAt": "...", "issuedAt": "...",
    "verification": { "level": 3, "methods": ["keypad_knowledge", "photo_id"] },
    "records":  [{ "recordId": "...", "formId": "...", "digest": "<sha256 hex>" }],
    "payments": [{ "paymentId": "...", "status": "paid", "amountMinor": 15000, "currency": "cad", "providerRef": "cs_..." }],
    "consents": [{ "purpose": "...", "wordingVersion": "1", "wordingDigest": "<sha256 hex>", "answer": "yes" }],
    "ledger":   { "seq": 17, "hash": "<sha256 hex>" }
  },
  "alg": "ES256",
  "kid": "...",
  "signature": "<base64url of the 64-byte r||s signature over canonicalJson(body)>"
}
```

`ledger` is the head after `call.ended`. `verifyReceipt(receipt, keys)` picks the key by `kid`
and returns false for any change, a wrong algorithm, a malformed signature or an unknown key.
Record digests are `SHA-256(canonicalJson({formId, version, values}))`; wording digests are
`SHA-256(canonicalJson({purpose, version, text: {en, fr}}))`.

## 8. Intake values

| Type | Accepted | Stored as |
|---|---|---|
| `text` | trimmed, non-empty, at most `maxLength` (500), and no card number | string |
| `number` | `-?\d+(\.\d+)?` | number |
| `date` | `YYYY-MM-DD` naming a real day | string |
| `yes_no` | `yes`, `y`, `oui` / `no`, `n`, `non`, any case | boolean |

Forms need snake_case unique keys and an English and a French label per field. Fields marked
`sensitive` are refused until field encryption exists (FIL-2).

## 9. Payments

`requestPayment` needs `payment.request`, a positive integer amount in minor units up to the
engine's limit (at most 1,000,000), a lower-case ISO 4217 currency and a 1 to 200 character
description. One link at a time per call. Settlement:

| Provider outcome | Status |
|---|---|
| completed, `payment_status: paid` | paid |
| completed, `unpaid` | none yet (wait for the asynchronous result) |
| completed, `no_payment_required` | failed |
| async payment succeeded | paid |
| async payment failed | failed |
| expired | expired |

A request settles once; later outcomes are ignored.

## 10. Stripe webhooks

`verifyStripeSignature` follows Stripe's published scheme: the `Stripe-Signature` header has
`t=<unix seconds>` and one or more `v1=<hex>`; each `v1` is `HMAC-SHA256(secret, t + "." + raw
body)`. The check passes if any `v1` matches any configured secret and `t` is within 300 seconds
of now, either way. `parseStripeEvent` maps
`identity.verification_session.{verified,requires_input,canceled}` and
`checkout.session.{completed,async_payment_succeeded,async_payment_failed,expired}`; other types
are reported as ignored, and a body that is not a well-formed event is `null`.

## 11. Texts

Code builds every text, in the call's locale (English or French). The destination is always the
subject's number on file. Identity link: "Your one-time identity check link: URL" / "Votre lien
de vérification d'identité, à usage unique : URL". Payment link: "Your secure payment link for
AMOUNT: URL" / "Votre lien de paiement sécurisé pour AMOUNT : URL", with the amount formatted in
the currency's own decimals.
