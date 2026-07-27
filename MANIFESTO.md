# The Digital Legacy Manifesto

**A statement of principles for the Digital Legacy Protocol**

**Author:** Ciprian Ștefan Pleșca
**Repository:** [github.com/Ciprian-LocalPulse/digital-legacy-protocol](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol)
**Companion to:** [WHITEPAPER.md](WHITEPAPER.md) (technical argument) and [spec/SPEC.md](spec/SPEC.md) (normative specification)
**License:** CC0 1.0 — public domain, matching the specification it accompanies.
**Date:** July 2026

---

## Preamble

A specification describes how a system works. A whitepaper argues why it is sound. Neither document is well suited to stating, plainly and without hedging, what the system is *for* — and what it refuses to become. This manifesto exists to do that.

Everything below is a claim someone could disagree with. That is the point. A manifesto that nobody could contest is not a manifesto; it is a mission statement, and mission statements do not survive contact with the incentives that killed every previous attempt at this problem.

---

## I. The problem is not technical, and pretending otherwise is a form of avoidance

Shamir's Secret Sharing has been public since 1979. Public-key signatures have been a solved engineering problem for decades. Every cryptographic primitive this protocol depends on predates it by a generation. If digital inheritance remained unsolved through 2026, the missing ingredient was never a better algorithm.

What was missing was the will to build something nobody could profit from owning. A bank has no incentive to build a system that lets a customer's assets move to their children without a probate fee changing hands somewhere along the way. An exchange has every incentive to keep "what happens when the account holder dies" as vague as its terms of service will permit, because vagueness defers a cost. A password manager can offer an "emergency access" feature as a retention mechanism precisely because it is proprietary — a feature, not a standard, is something a user cannot take with them if they switch providers.

We name this plainly because a protocol that misdiagnoses its own obstacle will optimize for the wrong thing. DLP is not trying to be a better piece of cryptography. It is trying to be a piece of infrastructure that nobody has a reason to prevent.

## II. No institution should get to unilaterally decide that a person is gone

This is the load-bearing principle of the entire protocol, and every other design choice follows from it.

A platform's support department deciding, on the basis of an inactivity timer and a scanned death certificate of uncertain provenance, whether to release someone's assets is a single point of failure wearing the costume of due process. It fails in both directions: it is too slow and too suspicious when the death is real, and it is too easily satisfied by a forged document when it is not. Worse, it concentrates a decision that should belong to people who actually knew the owner — family, friends, a lawyer, a business partner — inside an organization whose only relationship to the owner was custodial.

DLP replaces that single point of institutional discretion with a quorum of humans the owner chose while alive, each of whom stakes their own name on an attestation, and any one of whom can stop the process outright if something looks wrong. This is not a technological improvement over platform discretion. It is a *categorically different kind of authority* — distributed, personal, and revocable up to the last moment — and we consider that difference to be the protocol's entire reason for existing.

## III. A secret an implementation can access is a secret that will eventually leak

Every custodial system that has ever held sensitive material at scale has eventually disclosed some of it — through breach, through insider access, through a subpoena the user never anticipated, or simply through the platform's own product decisions years after the user stopped paying attention. This is not a claim about any particular company's competence. It is a structural observation: a whole secret sitting in one place is a whole secret waiting for one sufficiently motivated or sufficiently careless party to reach it.

The protocol's response is not to trust its own implementation more carefully. It is to ensure the implementation has nothing worth stealing. Below the quorum threshold, Shamir's Secret Sharing reveals *zero information* about the protected secret — not "computationally difficult to recover," but information-theoretically absent, in the same sense that a coin flip you haven't observed is not "hard to know," it is not yet a fact. No audit of DLP's servers, because DLP has no servers holding whole secrets to audit. This is a stronger claim than "we take security seriously," and we make it because it is the only kind of claim a system handling irreversible loss is entitled to make.

## IV. A standard that requires permission to adopt is not a standard

DLP's specification is released under CC0 — public domain, no attribution required, no license to negotiate. This is a deliberate rejection of a more common pattern in infrastructure projects: open enough to attract goodwill, restrictive enough to retain leverage over whoever eventually wants to build on it commercially.

We reject that pattern because leverage is precisely what makes a standard fail to become one. A password manager evaluating whether to implement `DLPAdapter` should never have to route the decision through a legal team weighing licensing risk. A bank should be free to implement this specification, charge for the product built around it, and never owe this project anything — not attribution, not revenue share, not a courtesy email. The measure of this protocol's success is not how much value it captures. It is how completely it can be forgotten as a named thing once enough platforms simply do what it describes.

## V. Honesty about limitation is not a caveat appended to the work — it is part of the work

A system whose entire purpose is activating on the basis of a claim about someone's death or incapacity carries a correspondingly unusual obligation: overstating its maturity is not a marketing misstep, it is a way of getting someone's inheritance wrong at the exact moment no one involved can go back and check the reasoning.

Accordingly, this project treats an explicit account of what remains unbuilt, untested, or unresolved as a first-class deliverable — not a footnote demanded by due diligence, but load-bearing content that belongs in the README and the whitepaper with the same prominence as the features that work. Where the specification is tested and the cryptography sound, we say so without hedging. Where legal standing for trustee attestation is entirely unresolved — because it is, and no version bump changes that a lawyer in a specific jurisdiction has to answer it — we say that too, in the same document, at the same volume.

We hold this position because we believe the alternative — the customary practice of foregrounding capability and relegating limitation to a disclaimer nobody reads — is a disservice specifically unsuited to software whose failure mode is a grieving family discovering, too late, that a feature they relied on had never actually been tested.

## VI. The protocol must survive its author

Software tied to the continued participation of the person who wrote it is a poor foundation for something explicitly designed to activate after someone is gone — and that observation applies as much to DLP's own maintainer as to any platform DLP was built to route around.

This is why the specification is versioned, public-domain text rather than a hosted service; why the reference implementation deliberately depends on nothing but a single well-audited cryptography library; why `dlp/shamir.py` is implemented from first principles specifically so it can be read and verified without trusting an external dependency's supply chain; and why the long-term intention, stated in [CONTRIBUTING.md](CONTRIBUTING.md) and formalized in [GOVERNANCE.md](GOVERNANCE.md), is for decision-making to move toward a structured, multi-maintainer process as the project grows, rather than remaining a single point of continuity risk indefinitely. A protocol about surviving one's own absence should not itself depend on its author's presence to keep functioning.

## VII. What this project will not become

- **Not a custodian.** DLP will never hold a whole secret on a user's behalf. If a future version of this project proposes doing so, that proposal should be read as a departure from this manifesto, not an extension of it.
- **Not a platform.** There is no DLP account to create, no DLP dashboard collecting usage data, no DLP entity positioned between an owner and their trustees. The reference web UI is explicitly, permanently local-and-single-user by design — see [spec/SPEC.md, Section 14](spec/SPEC.md) — and any hosted, multi-tenant version is a different piece of software built *on* this specification, not a mode this project intends to offer itself.
- **Not a monetization vehicle.** The specification is CC0 so that no commercial interest, including the maintainers' own, can ever require anyone's permission to adopt it. Donations, described in [DONATIONS.md](DONATIONS.md), fund maintenance; they do not purchase influence over the standard.
- **Not a legal instrument.** DLP is a technical layer a will can reference, not a substitute for one. Trustee-quorum attestation carries whatever legal standing a specific jurisdiction chooses to give it — a question this project cannot answer through engineering and does not pretend to.

## VIII. An invitation, not a pitch

This manifesto is not asking anyone to trust a company, join a waitlist, or adopt a token. It is asking implementers, researchers, and platforms to read a public-domain specification and decide, on the specification's own merits, whether it describes something worth building against. If it does not, the correct response is to say so in an issue — [spec critique from people who are not engineers is explicitly welcome](CONTRIBUTING.md), because this is meant to work for families, not only for developers.

If it does, the correct response is to build the next adapter, port the manifest format to another language, or find the edge case the specification handles badly — and in doing so, make this project's stated goal a little closer to true: that in time, nobody needs to know the name "Digital Legacy Protocol" at all, because enough of the services people actually use simply do, by default, what a person asked them to do.
