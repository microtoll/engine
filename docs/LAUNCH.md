# Launch checklist

The founder executes this, in order, each item a tick. Until the first item
is done nothing leaves this machine (the publish gate, DECISIONS.md D-01).
Plan §2: no promotion beyond the last two items.

1. [x] **D-01 recorded open** in `DECISIONS.md`: the IP and employment
       checks have passed. (2026-09-27.)
2. [ ] **The repository** on GitHub, private first; this history pushed; the
       licences present; branch protection on `main`. (Pushed 2026-09-27 and
       moved the same day into the `microtoll` organisation, private:
       `microtoll/engine-record` holds this dated history, `microtoll/pqc-scan`
       sits beside it. Branch protection remains: on a private repository
       GitHub offers it only with a paid plan (Team, for an organisation), so
       it is set either then or on the public repository at item 7.)
3. [x] **A signing key** made (2026-09-27, `~/.ssh/microtoll-release`, verified on GitHub) (`ssh-keygen -t ed25519 -C microtoll-release`;
       `git config gpg.format ssh` and `git config user.signingkey ~/.ssh/microtoll-release.pub`);
       its public half added to `SECURITY.md` and to the GitHub account as a
       signing key.
4. [~] **The npm organisation `@microtoll`** created (it was, under the
       founder's account; `@microtoll/pqc-scan` 0.1.0 published from it on
       2026-09-27); publishing restricted
       to provenance from this repository's release workflow (trusted
       publishing), no long-lived token.
5. [ ] **Versions**: every `packages/*/package.json` at `0.1.0` and its
       `"private": true` line removed (the first publish; lockstep, D-41).
6. [ ] **The repository variable `PUBLISH_GATE_OPEN`** set to `true`.
7. [ ] **The public repository, from a snapshot** (decided 2026-09-27): the
       private repository (`microtoll/engine-record`) stays private as the
       dated record; a new public repository, `microtoll/engine` (the name
       the documentation links to), starts from a snapshot of the tree, its
       first commit saying where the private history is kept. Nothing is
       rewritten. `microtoll/pqc-scan` can be made public as it is: its
       history names no other product (done 2026-09-27, at `19eec51`; its
       tag waits on items 3 and 4). Items 2, 3
       and 6 (branch protection, the signing key, `PUBLISH_GATE_OPEN`) are
       repeated for it. Then tag: `git tag -s v0.1.0 -m "Microtoll Engine 0.1.0"`
       and push the tag; the release workflow publishes with provenance.
8. [ ] **Provenance checked** on npm for each of the six packages.
       (`pqc-scan` 0.1.0 was published by hand, without provenance; its
       next version comes through `release.yml` once trusted publishing is
       set.)
9. [ ] **microtoll.dev**: the domain's DNS to GitHub Pages; the Pages
        workflow enabled for `docs/site`; `https://microtoll.dev/llms.txt`
        answers.
10. [ ] **security@microtoll.dev** exists and is read.
11. [ ] **The MCP server listed** in the MCP registry and the hosts'
        directories, as `@microtoll/mcp`.
12. [ ] One **Show HN** post. A **GitHub Sponsors** link. Nothing else.

