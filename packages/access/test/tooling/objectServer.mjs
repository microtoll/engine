// The object, member, pointer and share-link protocol as an extension of the
// identity package's fake server: an in-process stand-in for blind-store (M4)
// on the wire, with capabilities by hash, epoch guards on every write,
// rotation refused unless it names every active row, atomic link redemption
// and link limits. It keeps this package's tests free of a database; the
// message shapes here are the contract blind-store keeps.
export const URL_INVITE_MAX_USES = 50;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function objectProtocol({ cryptoCore: cc, db, users, b64u, fromB64u }) {
  const hashOf = async (b64) => { try { return b64u(await cc.sha256(fromB64u(b64))); } catch { return null; } };
  const obj = (id) => db.objects.get(id);
  const activeRows = (objectId) => [...db.rows.values()].filter((r) => r.objectId === objectId && r.status === 'active');
  const isAdmin = async (o, secret) => o && typeof secret === 'string' && (await hashOf(secret)) === o.adminHash;
  const isReader = async (o, secret) => o && typeof secret === 'string' && (await hashOf(secret)) === o.readHash;
  const rowBy = async (objectId, secret) => { const h = typeof secret === 'string' ? await hashOf(secret) : null; return h ? activeRows(objectId).find((r) => r.rowHash === h) || null : null; };
  const rowOut = (r) => ({ id: r.id, encryptedParticipationDataBlob: r.blob, keyEpoch: r.keyEpoch });

  return async ({ msg, rid, send, user, routing }) => {
    const fail = (reason, extra = {}) => { send({ type: `${msg.type}-failed`, reason, ...extra }, rid); return true; };
    switch (msg.type) {
      case 'create-event': {
        if (!user) return fail('no-account');
        if (!UUID_RE.test(msg.eventId || '') || typeof msg.encryptedEventData !== 'string') return fail('invalid');
        if (db.objects.has(msg.eventId)) return fail('already-exists');
        const cp = msg.creatorParticipation;
        db.objects.set(msg.eventId, { id: msg.eventId, content: msg.encryptedEventData, detail: msg.encryptedEventDetail || null, epoch: 1, adminHash: msg.adminCapabilityHash, readHash: msg.readCapabilityHash, status: 'active', membersOnly: msg.rosterMembersOnly === true, selector: { collection: msg.collection, selector: msg.selector, windowStart: msg.windowStart, windowEnd: msg.windowEnd } });
        db.rows.set(cp.eventUserId, { id: cp.eventUserId, objectId: msg.eventId, blob: cp.encryptedParticipationDataBlob, sharedKey: cp.encryptedSharedEventKey, rowHash: cp.rowCapabilityHash, keyEpoch: cp.keyEpoch, status: 'active' });
        const pid = `p${db.pointerSeq++}`;
        db.pointers.set(pid, { id: pid, owner: routing, blob: msg.pointer.encryptedEventAccessBlob });
        send({ type: 'create-event-ok', eventId: msg.eventId }, rid); return true;
      }
      case 'fetch-event': {
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active') return fail('not-found');
        send({ type: 'event', event: { id: o.id, encryptedEventData: o.content, encryptedEventDetail: o.detail, keyEpoch: o.epoch, adminCapabilityHash: o.adminHash, ...o.selector } }, rid); return true;
      }
      case 'join-event': {
        if (!user) return fail('no-account');
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active') return fail('event-not-found');
        if (msg.participation) {
          if (!(await isReader(o, msg.readCapabilitySecret))) return fail('unauthorized');
          if (msg.participation.keyEpoch !== o.epoch) return fail('stale');
          const p = msg.participation;
          db.rows.set(p.eventUserId, { id: p.eventUserId, objectId: o.id, blob: p.encryptedParticipationDataBlob, sharedKey: p.encryptedSharedEventKey, rowHash: p.rowCapabilityHash, keyEpoch: p.keyEpoch, status: 'active' });
        }
        const pid = `p${db.pointerSeq++}`;
        db.pointers.set(pid, { id: pid, owner: routing, blob: msg.pointer.encryptedEventAccessBlob });
        send({ type: 'join-event-ok', eventId: o.id }, rid); return true;
      }
      case 'fetch-event-members': {
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active') return fail('unauthorized');
        const ok = o.membersOnly
          ? (await rowBy(o.id, msg.rowCapabilitySecret)) || await isAdmin(o, msg.adminCapabilitySecret)
          : await isReader(o, msg.readCapabilitySecret) || await isAdmin(o, msg.adminCapabilitySecret);
        if (!ok) return fail('unauthorized');
        send({ type: 'event-members', members: activeRows(o.id).map(rowOut) }, rid); return true;
      }
      case 'rotate-event-key': {
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active' || !(await isAdmin(o, msg.adminCapabilitySecret))) return fail('unauthorized');
        if (!Number.isInteger(msg.expectedEpoch) || !Array.isArray(msg.updates)) return fail('invalid');
        if (o.epoch !== msg.expectedEpoch) return fail('stale', { detail: 're-keyed since this plan was built' });
        if (o.detail && !msg.encryptedEventDetail) return fail('invalid', { detail: 'a rotation must re-seal the detail part' });
        const active = new Set(activeRows(o.id).map((r) => r.id));
        const named = [...msg.updates.map((u) => u.eventUserId), ...(msg.removedEventUserIds || [])];
        if (new Set(named).size !== named.length || named.length !== active.size || !named.every((id) => active.has(id))) return fail('stale', { detail: 'the plan does not name exactly the rows the event has now' });
        o.epoch += 1; o.content = msg.encryptedEventData; o.detail = msg.encryptedEventDetail || null; o.readHash = msg.readCapabilityHash; o.adminHash = msg.adminCapabilityHash;
        for (const u of msg.updates) { const r = db.rows.get(u.eventUserId); r.blob = u.encryptedParticipationDataBlob; r.sharedKey = u.encryptedSharedEventKey; r.keyEpoch = o.epoch; }
        for (const id of msg.removedEventUserIds || []) db.rows.get(id).status = 'removed_by_admin';
        send({ type: 'rotate-event-key-ok', keyEpoch: o.epoch }, rid); return true;
      }
      case 'fetch-my-participation': {
        const r = await rowBy(msg.eventId, msg.rowCapabilitySecret);
        if (!r) return fail('not-found');
        send({ type: 'my-participation', member: { id: r.id, encryptedParticipationDataBlob: r.blob, encryptedSharedEventKey: r.sharedKey, keyEpoch: r.keyEpoch } }, rid); return true;
      }
      case 'create-participation': {
        if (!user) return fail('no-account');
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active') return fail('event-not-found');
        if (!(await isReader(o, msg.readCapabilitySecret))) return fail('unauthorized');
        const p = msg.participation;
        if (p.keyEpoch !== o.epoch) return fail('stale');
        const ptr = db.pointers.get(msg.pointerId);
        if (!ptr || ptr.owner !== routing) return fail('pointer-not-found');
        db.rows.set(p.eventUserId, { id: p.eventUserId, objectId: o.id, blob: p.encryptedParticipationDataBlob, sharedKey: p.encryptedSharedEventKey, rowHash: p.rowCapabilityHash, keyEpoch: p.keyEpoch, status: 'active' });
        ptr.blob = msg.pointer.encryptedEventAccessBlob;
        send({ type: 'create-participation-ok', eventUserId: p.eventUserId }, rid); return true;
      }
      case 'update-participation': {
        if (!Number.isInteger(msg.keyEpoch)) return fail('invalid');
        const r = await rowBy(msg.eventId, msg.rowCapabilitySecret);
        if (!r || r.keyEpoch !== msg.keyEpoch) return fail(r ? 'stale' : 'unauthorized');
        r.blob = msg.encryptedParticipationDataBlob;
        send({ type: 'update-participation-ok' }, rid); return true;
      }
      case 'update-event': {
        const o = obj(msg.eventId);
        if (!o || o.status !== 'active' || !(await isAdmin(o, msg.adminCapabilitySecret))) return fail('unauthorized');
        if (o.epoch !== msg.keyEpoch) return fail('stale');
        o.content = msg.encryptedEventData;
        if (msg.encryptedEventDetail) o.detail = msg.encryptedEventDetail; // COALESCE
        send({ type: 'update-event-ok' }, rid); return true;
      }
      case 'delete-event': {
        const o = obj(msg.eventId);
        if (!o || !(await isAdmin(o, msg.adminCapabilitySecret))) return fail('unauthorized');
        db.objects.delete(o.id);
        for (const [id, r] of [...db.rows]) if (r.objectId === o.id) db.rows.delete(id);
        send({ type: 'delete-event-ok' }, rid); return true;
      }
      case 'delete-participation': {
        const r = await rowBy(msg.eventId, msg.rowCapabilitySecret);
        if (r) db.rows.delete(r.id);
        send({ type: 'delete-participation-ok', deleted: Boolean(r) }, rid); return true;
      }
      case 'fetch-pointers': {
        send({ type: 'pointers', pointers: [...db.pointers.values()].filter((p) => p.owner === routing).map((p) => ({ id: p.id, encryptedEventAccessBlob: p.blob })) }, rid); return true;
      }
      case 'update-pointer': {
        const p = db.pointers.get(msg.pointerId);
        if (!p || p.owner !== routing) return fail('not-found');
        p.blob = msg.encryptedEventAccessBlob;
        send({ type: 'update-pointer-ok' }, rid); return true;
      }
      case 'create-url-invite': {
        if (!/^[0-9a-f]{64}$/.test(msg.hashedToken || '') || typeof msg.encryptedPayload !== 'string') return fail('invalid');
        if (!Number.isInteger(msg.maxUses) || msg.maxUses < 1 || msg.maxUses > URL_INVITE_MAX_USES) return fail('invalid', { detail: 'maxUses' });
        if (typeof msg.expiresAt !== 'string' || Number.isNaN(Date.parse(msg.expiresAt))) return fail('invalid', { detail: 'expiresAt' });
        if (typeof msg.manageCapabilityHash !== 'string') return fail('invalid', { detail: 'manageCapabilityHash' });
        if (db.links.has(msg.hashedToken)) return fail('token-collision');
        db.links.set(msg.hashedToken, { payload: msg.encryptedPayload, maxUses: msg.maxUses, useCount: 0, expiresAt: Date.parse(msg.expiresAt), manageHash: msg.manageCapabilityHash });
        send({ type: 'create-url-invite-ok' }, rid); return true;
      }
      case 'redeem-url-invite': {
        const l = db.links.get(msg.hashedToken);
        if (!l) return fail('not-found');
        if (l.expiresAt <= Date.now()) return fail('expired');
        if (l.useCount >= l.maxUses) return fail('exhausted');
        l.useCount += 1;
        send({ type: 'redeem-url-invite-ok', encryptedPayload: l.payload }, rid); return true;
      }
      case 'revoke-url-invite': {
        const l = db.links.get(msg.hashedToken);
        const h = await hashOf(msg.manageSecret);
        let revoked = 0;
        if (l && h && l.manageHash === h) { db.links.delete(msg.hashedToken); revoked = 1; }
        send({ type: 'revoke-url-invite-ok', revoked }, rid); return true;
      }
      case 'fetch-invite-token-stats': {
        const tokens = [];
        for (const q of msg.links || []) {
          const l = db.links.get(q.hashedToken);
          if (l && (await hashOf(q.manageSecret)) === l.manageHash) tokens.push({ hashedToken: q.hashedToken, useCount: l.useCount, maxUses: l.maxUses, expiresAt: new Date(l.expiresAt).toISOString() });
        }
        send({ type: 'invite-token-stats', tokens }, rid); return true;
      }
      default:
        return false;
    }
  };
}
