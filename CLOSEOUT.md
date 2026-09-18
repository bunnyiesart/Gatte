# CLOSEOUT.md — what stands between "v1 declared" and "v1 running"

Companion to `WORKFLOW.md`, which is the build order and ends when the
seven phases close. This file is the **order and the gates for what is
left after that**, and it exists because of one sentence in `WORKFLOW.md`'s
own closing block:

> It does NOT mean the deployment was exercised. Everything above runs on a
> development machine.

`design/adr/0026` closed the v1 criterion on 16 Sep 2026 and closed it
honestly: three conditions, all three met, **all three about this machine**.
No condition in it says anything about the gateway running anywhere. That is
not a defect in the criterion — a criterion that cannot be checked from a
clone is worse than one that can — but it does mean "v1" and "in service"
are two different claims, and only the first has been made.

This file is the second one.

## What this file is not

- **Not a new phase.** The seven phases are closed and nothing here reopens
  them. Every track below is either operating an existing artifact or
  checking an existing claim.
- **Not a reopening of the v1 criterion.** ADR-0026 is `Accepted`. Nothing
  here is a condition of v1; all of it is a condition of *trusting the
  deployment*, which v1 never claimed.
- **Not where the declared security limits go.** `README.md`'s security
  posture names three things this system does not do — no uid separation
  between the backends and the process holding every credential, no
  per-record signature on the trail, no bound on concurrent calls from an
  authorised analyst. Those are **declared limits, not debt**, they were
  decided rather than deferred, and closing them is a design decision with
  its own ADR, not a closeout task. They are listed in `AGENTS.md` §2 and
  they stay there.

## Progress

- [ ] **Track 1** — the deployment has never run this build
- [ ] **Track 2** — the anchor comparison has no owner
- [ ] **Track 3** — the older half of the design record has never been swept
- [ ] **Track 4** — the proofs skip silently where `sops` and `age` are missing
- [ ] **Track 5** — `lab/probe` as a second protocol client *(filed; not required to close)*

Track 1 is the only one that needs a host. Tracks 2–4 are checkable from a
clone and can run in any order, before or after it.

---

## Track 1 — the deployment has never run this build

### What is true now, measured

The last **successful** provisioning of the jail was 12 Sep 2026. Since
then, eight ADRs have been accepted: `0020`–`0023` on 15 Sep and
`0024`–`0027` on 16 Sep. Among them are a periodic registry reconciliation
that changes what a running gateway does every tick (`0020`), a vault that
re-reads its file (`0023`), a per-call deadline (`0025`), and a rate limiter
in the authentication-failure path (`0027`). None of those has ever run
outside a test binary.

A provisioning run **was** attempted on 16 Sep and it stopped, correctly, at
the vault check: this repository names four sanitised backends and the jail
runs four differently-named ones, so the run would have registered four
extra upstreams against vault entries nobody seeded. That is what
`UPSTREAM_NAMES`/`UPSTREAM_CREDS` were built for (commit `6c2bc9b`), and
**those variables have never been exercised against the real host** — the
mechanism is written and unproven.

One change did reach the jail by hand that day: the signing key was moved
off the service account (`chown root:wheel`, `chmod 600`) and the service
restarted. So the running host is in a state no script produced and no
script has since reproduced.

### The work

1. Re-run provisioning with the override, from `deploy/gateway-serve.md`:

       UPSTREAM_NAMES="…" UPSTREAM_CREDS="…" ./deploy/gateway-serve.sh

   Neither variable belongs in a tracked file. Expect the run to get as far
   as staging `mock-<name>` and stop, because those packages exist only
   under the sanitised names — that is documented and is not a failure of
   the override. Past the lab phase an upstream points at a real MCP
   server, not at a mock this repository ships.

2. Re-sign every registry entry. `require_signed` defaults true, and an
   entry whose signature no longer verifies is taken out of service within
   one `quarantine.refresh_interval` rather than at boot (`0020`) — so a
   missed entry shows up as a backend that quietly stops being served, not
   as a startup error.

3. Watch one refresh interval before declaring anything. `0020`, `0023`,
   `0024` and `0027` are all *tick-scoped* or *load-scoped*: none of them
   proves itself at startup.

### Gate

`deploy/gateway-serve-verify.sh` passes against the host, **and** the
startup summary names the telemetry destination, the trusted-key count and
every upstream that failed to come up. A verifier that passes while the
service is down is the failure this deployment has already had once — the
provisioning script stops the service early on purpose, so read the trap
output, not just the exit code.

### What this track deliberately does not cover

Cold-start cost per connection, and anything about capacity. The gateway is
a declared single point of failure (`0001`) and nothing here measures what
it does under the SOC's real call volume.

---

## Track 2 — the anchor comparison has no owner

### What is true now

`deploy/gatte-anchor-verify.sh` exists, works, and compares the trail's
chain head against the SIEM's copy. `WORKFLOW.md` says running it "is still
a human's job". **No human is named, and nothing detects that it did not
run.**

This matters more than a missing rota. Per `0015`'s correction block, the
chain is an unkeyed SHA-256 in the table it authenticates, so an attacker
who re-chains forward verifies clean; comparing the two heads is not a
footnote to the chain, it **is** the detection. An undetected absence of
that comparison is an undetected absence of the control.

The heartbeat (`0021`) closes the adjacent hole — a chain that went quiet is
now distinguishable from a quiet night — but the heartbeat is unsigned and
says nothing about whether anyone compared the heads.

### The work

Two acceptable outcomes, and choosing is the point:

- **Name an owner and detect absence.** A person, a cadence, and an alert
  that fires when the comparison has not been recorded within that cadence.
  The Graylog recipe for "lines stopped arriving for this chain" is in
  `deploy/freebsd-jail.md` and is the shape to copy.
- **Or state plainly that nobody runs it**, in `README.md`'s security
  posture, and downgrade the claim accordingly: the anchor is evidence only
  when someone happens to look.

The second is a worse posture and a better document than the current state,
which asserts a control with no owner.

### Gate

`README.md` and `WORKFLOW.md` agree with each other and with reality, and if
an owner was named, an alert exists that fires on absence — tested by not
running the comparison, not by reasoning about it.

---

## Track 3 — the older half of the design record has never been swept

### What is true now

Five adversarial review rounds covered the code, the deployment, and every
document written from `0020` onward. **ADRs `0001`–`0019`, `CONCEPTS.md` and
`DEVELOPMENT-LOG.md` have never been checked against the system as it now
is.** `WORKFLOW.md` declares this, which is what makes it a gap rather than
hidden debt — but declaring it is not closing it.

The base rate argues for doing this: each of the five rounds found controls
documented as working that could not fire, and the last round audited the
whole system rather than a diff and still found three false claims. The
older documents have had no such pass and have had more time to drift.

### The work

One pass per document, asking only the question the earlier rounds asked:
**does this sentence describe the system, and can I make it fail?** Not
prose quality, not consistency of tone.

Known to check first, because later ADRs moved ground under earlier ones:

- `0004`'s retry — reworded by `0020`, which found it "existed only on
  paper". Verify nothing else in `0001`–`0019` still describes the old
  behaviour.
- `0010`'s trust anchor — `0020` changed signature verification from a
  once-per-process event to a per-tick one, and `0020`'s own correction
  block notes that pulling a key from `signer.trusted_keys` still needs a
  restart.
- `0013`'s quarantine window — the same "between two ticks" trade now
  appears in three places and should say the same thing in all of them.
- `0012`'s audit completeness — `0027` bought rate limiting with a real
  loss: the trail stops answering "how many" authentication failures.
  `0012` should not still imply it answers that.

### Gate

`internal/fitness`'s `TestCitedTestsExist` already fails when a document
names a test that does not exist; it does not and cannot check whether a
sentence is true. So the gate here is a written record of the sweep — which
documents were read, what was found, what was corrected — in
`DEVELOPMENT-LOG.md`. A sweep with no record is indistinguishable from one
that did not happen, which is the same argument Track 2 makes.

---

## Track 4 — the proofs skip silently where `sops` and `age` are missing

### What is true now, measured 18 Sep 2026

With `sops`, `age` and `age-keygen` absent from `PATH`:

| package | tests skipped |
|---|---|
| `cmd/mcp-gateway` | 11 |
| `internal/vault/sopsage` | **11** |

Every one of the 11 in `sopsage` skips with the same reason —
`age-keygen not found on PATH (required by design/adr/0005)` — and that set
includes `TestResolveThenSpawnDoesNotLeak`, which this repository calls the
single most important test in the project.

**`WORKFLOW.md` line 660 and `design/adr/0026` line 98 both say 9.** The
number was accurate when written and `0023` then added four tests to that
package. It is the defect this repository keeps finding in itself: a count
that reads as verified and is not. `WORKFLOW.md` is corrected; ADR-0026 is
`Accepted` and takes a correction block rather than an edit, which is a
decision for whoever opens it.

`make test` prepends `GOPATH/bin`, which is why the tests run here. Nothing
makes them run anywhere else, and nothing fails when they do not.

### The work

Decide which of these the project wants, and say so out loud:

- **Fail loudly.** `make check` refuses to pass when the three binaries are
  absent. Strongest, and it makes `make devtools` a hard prerequisite
  rather than a suggestion.
- **Report and continue.** The run prints a summary line naming how many
  proofs did not execute. Weaker, but it removes the silence, which is the
  actual defect — a suite that reports success having skipped the leak test
  is making a claim it did not check.

Either beats the current state. The counts above should come from the tool,
not from a document, so that they cannot drift again.

### Gate

A run without the binaries produces an outcome a reader cannot mistake for
a clean pass, and no document states a skip count that a command does not
produce.

---

## Track 5 — `lab/probe` as a second protocol client *(filed, not required)*

`0026` item 3 filed this rather than refusing it, and the reason it gave
still holds: the argument for building it was never "the property is not
proved" — it is proved, three ways. It is that `lab/probe` is a **different
implementation of the client protocol**, and two implementations find what
one does not.

Whoever builds it is not redoing a proof; they are adding a second client.
It is listed here so that it stays visible, and it is explicitly **not** a
condition of closing this file.

---

## Definition of done for closeout

1. **Track 1's gate passes against the real host**, with the startup
   summary read rather than the exit code trusted, and one full refresh
   interval observed.
2. **Tracks 2, 3 and 4 each end in a written artifact** — a named owner and
   an absence alert, or a downgraded claim; a sweep record in
   `DEVELOPMENT-LOG.md`; and a test run whose skips cannot be mistaken for
   passes.
3. **No document in this repository states a number that a command does not
   produce.** Track 4 exists because two of them did.

What "done" will still not mean, and this is written now rather than
discovered later: nothing above measures capacity, nothing above closes the
three declared limits in `README.md`'s security posture, and nothing above
makes the trail's integrity survive an attacker who controls the host. Those
were decided, not deferred, and they are the honest shape of this system
rather than a list of things to get to.
