# PrintMaster transfer and release deployment

## Rollout order

1. Finish testing this preparation branch. It intentionally keeps the existing root utility and raw-main command working. It does not transfer the repository, configure DNS, or deploy anything.
2. Transfer `mstrhakr/scans` to **printmaster-org/scans**, preserving the repository name. Transfer before merging this preparation PR. GitHub normally redirects repository links, but explicitly verify old clone and raw-content URLs; do not recreate a repository at the old location.
3. Update the local remote to the transferred repository using your SSH host alias as appropriate. Verify Actions is enabled and allowed actions are permitted by organization policy. Verify the `main` protection still requires PRs, up-to-date branches, and **Required checks**, including for admins. Check the transferred PR and CI runs under the new owner.
4. Merge the preparation PR after CI passes. The release workflows intentionally refuse publication from any other repository. The old command still uses the root utility during bootstrap.
5. Configure GitHub Pages and DNS as below.
6. Run **Prepare release** from `main`, supplying a new stable SemVer tag. The latest historical tag at preparation time was `2.0.2.0`; `v2.1.0` is a reasonable next feature release. Old four-part tags are not renamed or parsed as SemVer.
7. Inspect the generated draft release, edit its generated notes, and manually test the downloaded utility on a disposable Windows VM. The draft includes `scans.ps1`, `release.json`, and `SHA256SUMS.txt`. Publish the draft **manually in GitHub**. The user's publish event triggers Pages deployment; do not replace that action with a workflow using `GITHUB_TOKEN`, whose resulting release event may not start another workflow.
8. Verify the Pages deployment, HTTPS, stable command, pinned command, version history, checksum list, and deliberate mismatch failures. Check both Windows PowerShell 5.1 and PowerShell 7.
9. Open a small **cutover PR**: move the utility to `src/scans.ps1`, move the single loader source from `loader/scans.ps1` to root `scans.ps1`, and update the site builder, utility tests, and documentation paths. The packager already recognizes the new utility location. Do not duplicate the utility or maintain two loader implementations. Test the old raw URL through its transfer redirect and the new organization URL after merge.
10. Publish the next release/site refresh after cutover so Pages uses the new canonical loader source. From this point both public commands select releases, and merging development changes no longer deploys utility code to users.

Do not switch the root entry point before the first stable manifest works: an absent manifest deliberately stops the loader rather than falling back to development code.

## Pages, domain, and permissions

- In the organization, verify ownership of `printmaster.work` for GitHub Pages using GitHub's supplied DNS TXT record.
- In repository **Settings > Pages**, select **GitHub Actions** as the source. Configure the custom domain **scans.printmaster.work**.
- Add a DNS CNAME for `scans` pointing to **printmaster-org.github.io**, not a repository path. Follow GitHub's current domain configuration instructions and remove conflicting DNS records.
- Once the certificate is provisioned, enable **Enforce HTTPS**. DNS and certificate provisioning can take time; do not advertise the new command before it works.
- Configure the `github-pages` deployment environment to allow `main` and stable release tags matching `v*`. Release-triggered deployments use tag refs, not `main`. A main-only environment rule would block those deployments. Optional required environment reviewers add a second explicit promotion approval.
- The prepare workflow has `contents: write` only in its draft job. Site generation has read-only repository access. Only deployment receives `pages: write` and `id-token: write`.
- Retain main protection. These workflows publish release assets and Pages artifacts, not commits. No bot bypass, PAT, or organization-wide policy relaxation is required.
- If moving/removing Pages later, remove or update its DNS mapping; do not leave a dangling custom domain.

Organization policies may disallow third-party actions or require environment approval. Resolve those settings explicitly rather than granting a broad bypass.

## Release and promotion model

**Prepare release** runs the same Windows PowerShell 5.1 / PowerShell 7 CI suite as PRs against the dispatched `main` commit. It packages the exact checked-out utility bytes, records the full commit SHA and source path, and creates an editable draft with GitHub-generated notes. Those notes aggregate merged PRs and contributors since the previous release; use the included GitHub comparison for individual commits. They are not a blindly concatenated commit log.

Existing release tags are historical identifiers. Only new stable tags of the form `vMAJOR.MINOR.PATCH` are accepted; leading zeroes, four-part versions, build suffixes, and prereleases are rejected. Drafts and prereleases never enter the stable catalog.

Publishing the draft triggers **Promote release and deploy Pages**. It runs CI, then:

1. Lists all published releases, ignoring drafts, prereleases, and historical four-part tags.
2. Downloads each stable release's script, metadata, and checksum file.
3. Verifies SHA-256, the tag's source commit, and byte identity with the recorded source file at that commit. Missing assets or mismatches fail deployment.
4. Generates the landing page output, a byte-identical copy of the shared loader, and `releases.json` containing the promoted version plus all verified version/hash entries.
5. Uploads and deploys one Pages artifact. Generated files are never committed to `main`.

The loader reads the stable pointer and selects an exact version/hash pair from the same manifest. It downloads a **version-specific asset**, never `/latest/` or raw `main`, verifies SHA-256, and executes only after success. A cached manifest can select an older valid release without mixing its checksum with a newer asset. Administrator privileges are required before the utility is launched.

`releases.json` is the machine-readable SHA listing; the site renders the same catalog with pinned commands and links to release notes. GitHub's "latest" label is not the channel authority: the deployed manifest's `stable` field is.

This protects against corruption and inconsistent or replaced assets. It does **not** independently authenticate the publisher if an attacker can change both the Pages deployment and release assets. No code-signing claim is made.

## Refreshing the site or recovering a release

Merging website changes does not automatically deploy them. Run **Promote release and deploy Pages** from `main` with an already-published stable version to refresh the site or explicitly select a previous stable version. Do not run it on a feature branch.

Publishing a new release automatically promotes that version after validation and successful deployment. If deployment fails, the existing Pages site and manifest remain live. Inspect the failed run and rerun after fixing the cause. A published GitHub release can exist before the stable endpoint promotes it.

Patch regressions with a new SemVer release rather than replacing assets or moving tags. Previous verified releases remain available for pinned installs. Redeploying an older stable pointer is available if a quick rollback is necessary.

Historical four-part releases remain available directly on GitHub but are not retroactively assigned hashes or claimed to have passed this new pipeline. Every published new SemVer release must have its expected assets; an incomplete or mutated release blocks catalog regeneration until corrected.

GitHub Pages deployments are serialized with `cancel-in-progress: false`. GitHub can replace pending runs when several publications are queued, so publish releases one at a time and verify the promoted version.

## Local validation

Install Pester 4.10.1 as described in the README, then run:

```powershell
pwsh.exe -NoProfile -STA -File .\tests\Invoke-Tests.ps1
node --test .\tests\site.test.cjs
```

For an offline site preview, create a fixture catalog with the same shape as the generated `releases.json` entries and run `tools/Build-Site.ps1` with `-CatalogPath`, `-StableVersion`, and a new `-OutputDirectory`. Fixtures must never be uploaded as production release metadata. Serve that generated directory using a local static server; do not execute its loader against unpublished fixtures.
