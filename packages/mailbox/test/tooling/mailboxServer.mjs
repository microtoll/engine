// The mailbox's server half as an extension of the identity package's fake
// server, behaving as blind-store's mailbox.js does on the wire: rows under
// labels, consumed rows served without their bundle and emptied, expiry
// required. blind-store's own suites prove the real thing; the shapes here
// are the contract.
export function mailboxProtocol({ db, b64u, fromB64u }) {
  db.drops = db.drops || new Map();
  let seq = 1;
  const uuid = () => globalThis.crypto.randomUUID();
  const parseIds = (ids) => {
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 500) throw new Error('missing or empty mailboxIds');
    return ids.map((m) => { const bytes = fromB64u(m); if (bytes.length !== 32) throw new Error('mailboxIds must be 32 bytes'); return m; });
  };
  return async ({ msg, rid, send, ws }) => {
    const fail = (reason, extra = {}) => { send({ type: `${msg.type}-failed`, reason, ...extra }, rid); return true; };
    switch (msg.type) {
      case 'send-invite': {
        let id;
        try {
          if (typeof msg.mailboxId !== 'string' || fromB64u(msg.mailboxId).length !== 32) throw new Error('mailboxId must be 32 bytes');
          if (typeof msg.encryptedBundle !== 'string') throw new Error('missing encryptedBundle');
          if (typeof msg.expiresAt !== 'string' || Number.isNaN(Date.parse(msg.expiresAt)) || Date.parse(msg.expiresAt) <= Date.now()) throw new Error('expiresAt is required and in the future');
          id = uuid();
          db.drops.set(id, { id, seq: seq++, mailboxId: msg.mailboxId, bundle: msg.encryptedBundle, consumed: false, expiresAt: Date.parse(msg.expiresAt) });
        } catch (e) { return fail('invalid', { detail: e.message }); }
        send({ type: 'send-invite-ok', inviteId: id }, rid);
        return true;
      }
      case 'poll-invites': {
        let ids;
        try { ids = new Set(parseIds(msg.mailboxIds)); } catch (e) { return fail('invalid', { detail: e.message }); }
        const invites = [...db.drops.values()].filter((d) => ids.has(d.mailboxId) && d.expiresAt > Date.now())
          .map((d) => ({ id: d.id, mailboxId: d.mailboxId, encryptedBundle: d.consumed ? null : d.bundle, consumed: d.consumed }));
        send({ type: 'invites', invites }, rid);
        return true;
      }
      case 'consume-invite': {
        if (typeof msg.inviteId !== 'string') return fail('invalid');
        const d = db.drops.get(msg.inviteId);
        if (d) { d.consumed = true; d.bundle = ''; }
        send({ type: 'consume-invite-ok' }, rid);
        return true;
      }
      case 'watch-invites': {
        try { parseIds(msg.mailboxIds); } catch (e) { return fail('invalid', { detail: e.message }); }
        send({ type: 'watch-invites-ok' }, rid);
        return true;
      }
      default:
        return false;
    }
  };
}
