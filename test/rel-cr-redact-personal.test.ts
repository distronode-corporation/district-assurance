// CodeRabbit's review of the 0.1.0 release diff (#149): the Stripe recorder's redactor kept a
// Checkout customer's name, email and address, so a recording paid with a real person's details
// would have written them into this public repository. They are redacted now, and the guard finds
// any that are left, in an event body held as JSON text and in a fixture file's escaped text alike.
import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { Redactor, leaks } from "./fixtures/stripe-real/redact.ts";

const session = {
  object: "checkout.session",
  customer_details: {
    address: { city: "Ottawa", country: "CA", line1: "1 Example Street", line2: "Unit 2", postal_code: "K1A 0B1", state: "ON" },
    business_name: "Example Business",
    email: "person@example.com",
    individual_name: "A Person",
    name: "A Person",
    phone: "+15555550100",
    tax_exempt: "none",
    tax_ids: [],
  },
  customer_email: "person@example.com",
  collected_information: { shipping_details: { name: "A Person", address: { line1: "1 Example Street", postal_code: "K1A 0B1" } } },
  payment_status: "paid",
};
const PERSONAL = ["Ottawa", "1 Example Street", "Unit 2", "K1A 0B1", "Example Business", "person@example.com", "A Person", "+15555550100"];

describe("the Stripe redactor removes a customer's personal details (#149 review)", () => {
  it("redacts every personal value under customer_details, shipping_details and customer_email, and keeps the rest", () => {
    const body = JSON.stringify(session, null, 2);
    const out = JSON.parse(new Redactor().json({ body }).body) as typeof session;
    for (const value of PERSONAL) assert.ok(!JSON.stringify(out).includes(value), value);
    assert.deepEqual(out.customer_details.address, { city: "[redacted]", country: "[redacted]", line1: "[redacted]", line2: "[redacted]", postal_code: "[redacted]", state: "[redacted]" });
    assert.equal(out.customer_details.email, "[redacted]");
    assert.equal(out.customer_details.name, "[redacted]");
    assert.equal(out.customer_email, "[redacted]");
    assert.equal(out.collected_information.shipping_details.name, "[redacted]");
    assert.equal(out.customer_details.tax_exempt, "none", "not personal");
    assert.equal(out.payment_status, "paid");
    assert.deepEqual(out.customer_details.tax_ids, []);
  });

  it("finds a personal value left in, in an event body and in a fixture file's escaped text", () => {
    const body = JSON.stringify(session, null, 2);
    for (const text of [body, JSON.stringify({ delivery: { body } }, null, 2)]) {
      const found = leaks(text);
      for (const value of PERSONAL) assert.ok(found.some((f) => f.includes(value)), `${value} in ${text.slice(0, 20)}`);
    }
  });

  it("finds nothing once redacted, and nothing in a null or empty customer", () => {
    const body = JSON.stringify(session, null, 2);
    const redacted = new Redactor().json({ delivery: { body } });
    assert.deepEqual(leaks(JSON.stringify(redacted, null, 2)), []);
    assert.deepEqual(leaks(JSON.stringify({ customer_details: null, customer_email: null })), []);
  });
});
