import test from "node:test";
import assert from "node:assert/strict";

import { ownerAdmission, unauthorizedMessage } from "../server/auth.mjs";
import { runWithLanguage } from "../server/i18n.mjs";

function connectionWith(admission) {
  return {
    admit() {
      if (admission instanceof Error) throw admission;
      return admission;
    },
  };
}

test("ownerAdmission admits a pre-verified owner PeerScope from DSH >= 0.2.3 WebServer without calling connection.admit", () => {
  let called = 0;
  const connection = {
    admit() {
      called += 1;
      return { rejection: 401 };
    },
  };
  const controller = new AbortController();
  const decision = ownerAdmission(connection, {}, { principal: { kind: "owner" }, signal: controller.signal });
  assert.deepEqual(decision, { ok: true });
  assert.equal(called, 0, "connection.admit must not be re-invoked when WebServer supplied peer");
});

test("ownerAdmission rejects non-owner or malformed WebServer peers without falling back to connection.admit", () => {
  const ownerFallback = connectionWith({ peer: { principal: { kind: "owner" } } });
  const nonOwnerPeers = [
    { principal: { kind: "member" } },
    { principal: { kind: "guest" } },
    { principal: { kind: "share" } },
    { principal: {} },
    {},
    null,
    "owner",
    0,
  ];
  for (const peer of nonOwnerPeers) {
    assert.deepEqual(
      ownerAdmission(ownerFallback, {}, peer),
      { ok: false, status: 403 },
      `supplied peer ${JSON.stringify(peer)} must fail closed to 403`,
    );
  }
});

test("ownerAdmission rejects an aborted WebServer peer or fallback peer with 401", () => {
  const aborted = new AbortController();
  aborted.abort();
  assert.deepEqual(
    ownerAdmission(connectionWith({ peer: { principal: { kind: "owner" } } }), {}, {
      principal: { kind: "owner" },
      signal: aborted.signal,
    }),
    { ok: false, status: 401 },
  );
  assert.deepEqual(
    ownerAdmission(connectionWith({ peer: { principal: { kind: "owner" }, signal: aborted.signal } }), {}),
    { ok: false, status: 401 },
  );
});

test("ownerAdmission admits the DSH owner principal via legacy connection.admit fallback", () => {
  const decision = ownerAdmission(connectionWith({ peer: { principal: { kind: "owner" } } }), {});
  assert.deepEqual(decision, { ok: true });
});

test("ownerAdmission rejects every non-owner principal", () => {
  const shapes = [
    { peer: { principal: { kind: "member" } } },
    { peer: { principal: { kind: "guest" } } },
    { peer: {} },
    { peer: null },
    {},
    null,
  ];
  for (const admission of shapes) {
    assert.deepEqual(ownerAdmission(connectionWith(admission), {}), { ok: false, status: 403 });
  }
});

test("ownerAdmission passes through DSH's rejection status", () => {
  assert.deepEqual(ownerAdmission(connectionWith({ rejection: 401 }), {}), { ok: false, status: 401 });
  assert.deepEqual(ownerAdmission(connectionWith({ rejection: 403 }), {}), { ok: false, status: 403 });
  // Malformed rejection codes fail closed to 403, never to an allow.
  assert.deepEqual(ownerAdmission(connectionWith({ rejection: "yes" }), {}), { ok: false, status: 403 });
  assert.deepEqual(ownerAdmission(connectionWith({ rejection: 200 }), {}), { ok: false, status: 403 });
  assert.deepEqual(ownerAdmission(connectionWith({ rejection: 999 }), {}), { ok: false, status: 403 });
});

test("ownerAdmission fails closed when the connection is broken", () => {
  assert.deepEqual(ownerAdmission(null, {}), { ok: false, status: 403 });
  assert.deepEqual(ownerAdmission({}, {}), { ok: false, status: 403 });
  const thrown = ownerAdmission(connectionWith(new Error("admission exploded")), {});
  assert.equal(thrown.ok, false);
  assert.equal(thrown.status, 403);
  assert.equal(thrown.error.message, "admission exploded");
});

test("ownerAdmission ignores a rejection property on a non-object admission", () => {
  assert.deepEqual(ownerAdmission(connectionWith("owner"), {}), { ok: false, status: 403 });
  assert.deepEqual(ownerAdmission(connectionWith(0), {}), { ok: false, status: 403 });
});

test("unauthorizedMessage localizes 401 and 403 explanations", () => {
  assert.match(runWithLanguage("zh", () => unauthorizedMessage(401)), /登录态已失效/);
  assert.match(runWithLanguage("zh", () => unauthorizedMessage(403)), /持有者/);
  assert.match(runWithLanguage("en", () => unauthorizedMessage(401)), /Session expired or not authenticated/);
  assert.match(runWithLanguage("en", () => unauthorizedMessage(403)), /Only the owner/);
});
