# The honest limits

What nothing here protects against, on one page, in plain words. Every
package's page repeats its own part; the
[threat model](threat-model.html) has the adversaries and the reasoning.

## A compromised device or page wins

If a script runs inside your page — an injected one, a bad dependency, a
browser extension with the wrong permissions — or the device itself is
compromised, everything the page holds is gone: the root key, the keys to
every object, the session. A trusted-device session is exactly as safe as
the unlocked device it sits on. This is why the examples ship with a strict
content security policy and no third-party script, and why the engine has
no dependencies to carry one in.

## Traffic shape is visible

The server, and anyone who can watch the wire, sees who connects and when,
how many rows an account holds, the sizes of ciphertexts, and the coarse
selector of every object (a map cell and a day in an events app; a shelf
in the notes example). While few people use a deployment, one active account is easy to
pick out. Hiding this would need mix-network routing, which is out of scope.

## A link is as private as the channel it travels through

The secret is in the URL fragment, which servers and link previewers do not
receive. The messaging app the link is sent through can read it unless that
chat is end-to-end encrypted. Where a link is posted is the real access
control.

## Nothing can be moderated in advance

The server cannot read content, so abuse handling starts with a report from
someone who can. The engine ships no reporting; an app that needs it builds its own.

## No server-side recovery

Lose every unlock method — the passkey and the recovery code — and the data
is lost to everyone, including the operator. There is no reset link because
there is nothing for one to reset.

## Quantum computers, honestly

Every public-key seal is classical (P-256) unless hybrid mode is on for
every recipient. A copy of a database taken today could be opened by a large
enough quantum computer, which does not yet exist. Hybrid mode protects only
what is sealed after it is switched on, and an object is only as protected
as its weakest member's copy of the key. Symmetric encryption (AES-256-GCM,
HKDF, SHA-256) is not materially weakened. The mailbox label is classical
by necessity: there is no standard post-quantum non-interactive key
exchange.

## Cooperative, not cryptographic

"Sign out everywhere" and withdrawing a link are honoured by honest clients.
Neither can take back a key that has already left. Removal re-keys the
future; it cannot un-read the past.

## What the server does learn

Per object: its collection, selector and window, its epoch, whether its
roster is members-only, the sizes of its parts. Per connection: the routing
key, the origin, which selectors it queried and watched, one object id per
link redeemed, which link hashes and mailbox labels it touched. Per account:
how many pointers and unlock methods it holds, and that it made an object, a
link or a drop today (deleted after two days). Everything else is ciphertext
or a hash. The full list, and what a database copy holds, is in the
[threat model](threat-model.html#6-microtollblind-store).
