# @microtoll/mailbox

Inviting a known person directly, with nothing to forward: a sealed, signed
invitation dropped under a **mailbox label only the two of them can
compute**, collected by the recipient's own client. The server holds rows
under labels it cannot compute, attribute or read. Web Crypto only; depends
on `@microtoll/crypto-core` and `@microtoll/identity`.

**Status:** published as `@microtoll/mailbox` on npm. Formats in
`FORMATS.md` (the label frozen by crypto-core's fixture file; the bundle
version 2).

## The model in one paragraph

Two people who hold each other's public keys share, for each calendar month,
a **label**: HKDF over the P-256 agreement of their sealing keys, in one
direction. The sender drops a **bundle** under it — the object's key and
epoch, the sender's name and claims, signed with the mailbox and the
recipient bound in, then sealed to the recipient — and the recipient polls
the labels of everyone they know, opens what is theirs, and consumes it.
The sender polls the same labels to see who has collected, and can take an
uncollected drop back. An unsigned or re-sealed drop is usable but
attributed to nobody.

## Five-minute quickstart

```js
import { createCryptoCore } from '@microtoll/crypto-core';
import { createMailbox } from '@microtoll/mailbox';

const cc = createCryptoCore({ namespace: 'myapp' });
const mailbox = createMailbox({ cryptoCore: cc });

// A contact, as the app keeps it: the person's signing key and sealing key (base64url).
const bob = { signingKey: '…', identityKey: '…' };

// Alice invites Bob to an object she holds the key for.
const [sent] = await mailbox.send(ws, alice, [bob], { objectId, kObjectRaw, keyEpoch, senderName: 'Alice', claims: { greeting: 'hello' } });
keep({ identityKey: bob.identityKey, epoch: sent.epoch, inviteId: sent.inviteId });   // in Alice's own pointer

// Bob collects from everyone he knows: verified invitations, acknowledgements, and unsigned drops held for a tray.
const { invites, acks, unsigned, counts } = await mailbox.collect(ws, bobIdentity, contacts);
for (const inv of invites) {
  await joinTheObject(inv.objectId, inv.kObjectRaw, inv.keyEpoch, inv.senderName);   // the app's, with @microtoll/access
  await mailbox.consumeInvite(ws, inv.rowId);                                       // then it is collected
}

// Alice checks, or takes an uncollected one back.
const [{ collected }] = await mailbox.status(ws, alice, kept);
await mailbox.withdraw(ws, alice, cc.fromBase64Url(bob.identityKey), sent.epoch, sent.inviteId);

// Live: the labels Bob polls, watched; a drop wakes him.
const labels = await mailbox.receivingLabels(bobIdentity, contacts);
await mailbox.watchInvites(ws, [...labels.values()].map((l) => l.mailboxId));
mailbox.onLiveInvite(ws, () => mailbox.collect(ws, bobIdentity, contacts).then(show));
```

## What the app supplies

- **Contacts**: who this account knows (signing key and sealing key), kept
  in its identity blob; the invite example (`examples/invite-app`) records
  them from the rosters of notes the two share.
- **Policy**: which senders go straight through and which are held (an app
  might hold invitations from anyone not a favourite, and let a pairwise
  label be dismissed); who is blocked; whether an acknowledgement is
  recorded; any push subscription (`pushEpochs` gives its months).
  `collect` returns the drops and consumes only acknowledgements and
  unknown kinds (a retired kind is never acted on); the app consumes an
  invitation when it has acted on it.
- **The object side**: joining with the key in the invitation is
  `@microtoll/access` (a read-only pointer, then a first reaction).

## Tests

`npm test`: the label against crypto-core's frozen fixture from both ends,
the epochs, the bundle round trip and the re-sealing cases (a signed
invitation passed on to someone else verifies for nobody), the flows
against the server stand-in. blind-store's suites prove the server half.
