# @microtoll/mailbox — formats

Status: **decided** (2026-09-25). The label is frozen by the crypto-core fixture file (its `mailbox`
section, under the test namespace), which every later version must
reproduce; the bundle is version 2. Version-2 bundles this package wrote
under that label (an invitation, an acknowledgement and a hybrid invitation)
are frozen in `test/fixtures/frozen-v2.json`.

## 1. The label

```
shared = ECDH-P256(myPrivateSealingKey, theirPublicSealingKey)          (256 bits)
info   = "<ns>/invite-mailbox/v2|<YYYY-MM>|" + base64url(senderPublicKey) + "|" + base64url(recipientPublicKey)
label  = HKDF-SHA-256(shared, salt ∅, info, 256 bits)                    (32 bytes)
```

- The keys are the two long-term P-256 **sealing** keys (65-byte raw
  public keys). Both sides derive one value from opposite ends.
- The epoch is the calendar month in UTC. A recipient polls this month and
  the previous; a standing subscription covers this month and the next.
- `invite-mailbox/v1` (the X25519 label) is retired in every namespace
  and cannot be produced through the profile.
- What the server sees: the 32-byte label, and nothing else. It cannot
  compute one, attribute one, or read what is under it.

## 2. The bundle (version 2)

```
payloadJson = JSON { kind, objectId, kObject, keyEpoch, senderName, <claims…>, senderIdentityKey, senderSigningKey }
message     = frameContext("<ns>/sig/invite/v2", label, SHA-256(recipientKey)) ‖ UTF-8(payloadJson)
sig         = Ed25519(senderSigningKey, message)
bundle      = sealToRecipient(recipientKey, UTF-8(JSON { v: 2, payloadJson, sig }))
```

| Field | Invitation (`kind: "invite"`) | Acknowledgement (`kind: "invite-ack"`) |
|---|---|---|
| `objectId` | the object | the object the link opened |
| `kObject` | base64url of `K_object` | `null` |
| `keyEpoch` | the epoch the key is for | `null` |
| `senderName` | shown only when verified | shown only when verified |
| `hashedToken`, `stage` | — | which link was used; what is reported (`"seen"`, …) |
| claims | the app's own fields, inside the signed payload | the same |

- **What the signature binds**: the purpose label, the label of the mailbox
  the drop is for, and the hash of the key it is sealed to. A bundle re-sealed
  into another mailbox, or for another recipient, or with a changed
  payload, opens (the key in it is still a key) but verifies for nobody: no
  name, no claim.
- **Which recipient key:** `sealToRecipient` dispatches on the key's
  length — the classical sealing key (65 bytes, ECIES v3) or the hybrid KEM
  key (1216 bytes, ECIES v2, when the recipient advertises one). The
  bundle's first byte tells the recipient which of its keys to open with,
  and the signature is checked against that key.
- **Version 1 bundles are not read.** Version 1 signed `payloadJson` alone,
  so a contact could re-seal somebody else's signed invitation into a
  mailbox shared with a third person and it arrived as the signer's. No
  version 1 data exists to migrate.
- **Post-quantum:** the label is classical by necessity (no standard
  post-quantum non-interactive key exchange); the bundle is hybrid when the
  recipient's key is.

## 3. The server's part

`send-invite { mailboxId, encryptedBundle, expiresAt }` → `{ inviteId }`;
`poll-invites { mailboxIds }` → rows with the bundle for uncollected drops
and `consumed: true` without it for collected or withdrawn ones;
`consume-invite { inviteId }` (collection and withdrawal alike; the row's
bundle is emptied, so a collected or withdrawn drop keeps no key); `watch-invites { mailboxIds }` and the
`invite-live { mailboxId }` push. All in `@microtoll/blind-store`.
