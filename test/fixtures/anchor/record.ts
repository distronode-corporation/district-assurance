// Writes the recorded anchor fixtures (PRV-9): what a time-stamp authority and a Rekor v2 log
// answer for the head of `fixtureLedger()`. Run once with `node test/fixtures/anchor/record.ts`;
// the tests replay the files and never touch a network. The authority (an RSA root and a
// time-stamping certificate) and the log (an Ed25519 key) are throwaways made here, not a secret;
// the host key that signs the logged head is `fixtureSigner()`, so the adapter test can use it.
import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";

import { anchorPayload } from "../../../src/prove/anchor.ts";
import { FIXTURE_NONCE, REKOR_ORIGIN, certificate, der, fixtureLedger, fixtureSigner, hashedRekordBody, logEntry, pem, timestampResponse, timestampToken, OIDS } from "./build.ts";

const dir = new URL("./", import.meta.url);
const { ledger } = await fixtureLedger();
const payload = anchorPayload(await ledger.head());

const root = generateKeyPairSync("rsa", { modulusLength: 2048 });
const tsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const rootCert = certificate({ subject: "Test Root CA", issuer: "Test Root CA", publicKey: root.publicKey, signingKey: root.privateKey, serial: 1, notBefore: "260101000000Z", notAfter: "360101000000Z", ca: true });
const tsaCert = certificate({ subject: "Test TSA", issuer: "Test Root CA", publicKey: tsa.publicKey, signingKey: root.privateKey, serial: 2, notBefore: "260101000000Z", notAfter: "310101000000Z", usage: OIDS.timeStamping });
// The token names tsaCert in a SigningCertificateV2 and carries FIXTURE_NONCE, the nonce the adapter test asks with.
const token = timestampToken({ payload, time: "20261118120000.25Z", signingKey: tsa.privateKey, issuer: "Test Root CA", serial: 2, signerCertificate: tsaCert, nonce: der(0x02, FIXTURE_NONCE), certificates: [tsaCert] });
writeFileSync(new URL("tsa-chain.pem", dir), pem(tsaCert) + pem(rootCert));
// The DER TimeStampResp, kept as base64 text.
writeFileSync(new URL("tsa-response.der.b64", dir), `${timestampResponse(0, token).toString("base64")}\n`);

const log = generateKeyPairSync("ed25519");
const signer = fixtureSigner();
const body = hashedRekordBody(payload, sign("sha256", payload, signer.privateKey), signer.publicKey);
const entry = logEntry({ body, index: 9, size: 11, origin: REKOR_ORIGIN, logKey: log.privateKey, logPublicKey: log.publicKey });
writeFileSync(new URL("rekor-log.pem", dir), log.publicKey.export({ type: "spki", format: "pem" }));
// The checkpoint's signature lines start with U+2014, written escaped: the repository keeps that
// character out of its text files. The JSON is the same.
writeFileSync(new URL("rekor-response.json", dir), `${JSON.stringify(entry, null, 2).replace(/\u2014/g, "\\u2014")}\n`);
