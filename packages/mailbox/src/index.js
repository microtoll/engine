/**
 * @microtoll/mailbox — public entry point (M3b, D-40).
 *
 * Layers: labels.js (the pairwise label and its epochs), bundle.js (the
 * signed, sealed invitation or acknowledgement, version 2), wire.js
 * (the mailbox messages), collect.js (send, collect, withdraw,
 * status). `createMailbox` binds them to one crypto-core instance.
 */
import * as labels from './labels.js';
import * as bundle from './bundle.js';
import * as wire from './wire.js';
import * as collectApi from './collect.js';

export * from './labels.js';
export * from './bundle.js';
export * from './wire.js';
export * from './collect.js';

export function createMailbox({ cryptoCore: cc } = {}) {
  if (!cc) throw new Error('createMailbox needs a cryptoCore');
  const bind = (fns) => Object.fromEntries(Object.entries(fns).map(([k, f]) => [k, (...a) => f(cc, ...a)]));
  return Object.freeze({
    cc,
    epoch: labels.epoch, pollEpochs: labels.pollEpochs, pushEpochs: labels.pushEpochs,
    ...bind({
      mailboxId: labels.mailboxId, mailboxForSending: labels.mailboxForSending, mailboxForReceiving: labels.mailboxForReceiving,
      inviteSigningMessage: bundle.inviteSigningMessage, buildInvite: bundle.buildInvite, buildAck: bundle.buildAck, openBundle: bundle.openBundle,
      sendInvite: wire.sendInvite, pollInvites: wire.pollInvites, watchInvites: wire.watchInvites,
      receivingLabels: collectApi.receivingLabels, send: collectApi.send, collect: collectApi.collect, withdraw: collectApi.withdraw, status: collectApi.status,
    }),
    consumeInvite: wire.consumeInvite,
    onLiveInvite: wire.onLiveInvite,
  });
}
