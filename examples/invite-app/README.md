# Invites — the second example

What a share link cannot do: inviting a known person **directly**, with no
link and nothing to forward, through a mailbox only the two of you can
compute. Built on the notes example (`../notes-app/notes.js`) plus
`@microtoll/mailbox`; `invites.js` is everything this example adds (about
150 lines).

## Run it

```sh
cd examples/invite-app
docker compose up
```

Then open <http://localhost:8089>, in two browsers or a normal and a private
window, as Ada and Bea:

1. Both: **Boot**, **Sign up**, type a name.
2. Ada: **New note**, **share by link**; Bea pastes the link, **Open link**,
   then **join as member**.
3. Both: **remember people** on that note. Each now holds the other's keys
   from the note's own roster — nothing was exchanged with the server.
4. Ada: **New note**, then **invite Bea directly**. Bea's page is woken by
   the live watch and collects the invitation; the note appears with read
   access. Nobody made a link.
5. Bea: **open** it — her app tells Ada it was seen. Ada: **invitations**
   shows "collected, seen".
6. Ada: another note, **invite Bea directly**, then **take back** before
   Bea's page collects it. Bea's next collection finds nothing.

`docker compose down -v` throws the database away.

## What the server learns, honestly

- **Mailbox labels**: a 32-byte value per pair per month, written under by
  one connection and polled by another. It cannot compute a label (that
  needs one of the two private keys), attribute one, or pair the writer and
  the reader without both keys.
- **Which labels a routing key polls and watches** — one per contact per
  month, two months deep — so it learns how many people an account knows,
  not who.
- **That a routing key sent a drop today** (the daily counter), and each
  drop's expiry.
- Everything the notes example lists, since the notes are the same.

It does not learn a name, a note's key, who invited whom, or that an
invitation was seen (the acknowledgement is a drop like any other).

## Where things are

- `invites.js` — contacts from a roster, a direct invitation, collection,
  the acknowledgement on opening, withdrawal, the live watch.
- `page.js`, `index.html` — the page.
- `test/invites.test.mjs` — the story above, driven from Node against a real
  server and database (`node scripts/test-db.mjs up`, then `npm test`).
