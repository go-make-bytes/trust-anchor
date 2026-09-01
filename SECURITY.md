# Security policy

This service answers one question for everything downstream: *what is the current,
signature-verified set of EU trust anchors?* A wrong answer here does not fail loudly — it makes
every signature validation, Web eID login and wallet check that consumes it trust the wrong
certificate authorities. That is what makes its security surface worth reporting carefully.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/go-make-bytes/trust-anchor/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- the configuration it needs, if it only appears under particular settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

The one unacceptable failure mode of this service is serving **unverified** anchors. The classes
of problem that matter most are therefore the ones that undermine the verified chain from the EU
List of Trusted Lists to the bundle a consumer receives:

- an anchor served from a list whose XML signature was not verified, or was verified against a
  signer that is not in the pinned set;
- a way to change the pinned LOTL signer set, the pivot walk or the bootstrap so that a forged or
  stale list is accepted as genuine;
- a snapshot or bundle whose content does not match what was verified — a content address or
  snapshot identifier that does not correspond to the anchors it claims to hold;
- filters (territory, use, QSCD qualification) returning anchors they should exclude, or excluding
  anchors they should return, in a way a consumer would act on;
- reaching the operator-declared internal trust source, hold mode or refresh controls without
  the required authorisation;
- weakening or bypassing the security events that record a change in the trust inventory.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome only
where you can show the vulnerable path is actually reachable.

## Scope

This policy covers the code in this repository. It does not cover the EU or national trusted lists
themselves, the services that publish them, or third-party services the software talks to — report
those to the parties that run them — and it does not cover deployments operated by someone other
than us; ask their operator.

## Releases

The project has not yet published a release. Security fixes land on the default branch, and once
releases exist this section will name the versions that receive them.
