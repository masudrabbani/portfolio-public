# Audited public GitHub Pages preview

This public-only test copy was deployed with the owner's approval on October 23, 2026. GitHub Pages uses **GitHub Actions** as its publishing source. The published files passed an exact-content comparison with the reviewed static export.

Preview: <https://masudrabbani.github.io/portfolio-public/>. The official website remains <https://masudrabbani.com/>. Keep the custom-domain setting empty. Do not add `CNAME`, change DNS, alter the old private repository, or grant the Cloudflare GitHub app access to this new repository.

This preview is a published snapshot, not yet connected to automatic publishing from the private Cloudflare admin. A separately reviewed connection is needed before admin edits can update this repository. The existing admin and live website are unchanged.

## Only these files belong in the new public repository

- `.github/workflows/pages.yml`
- `verify_public_site.py`
- `README.md`
- `static-public.zip` — the already audited public static export only
- `public-manifest.json` — the matching public inventory and checksums

Do not upload this directory indiscriminately. `tests/` and `tools/` are local verification/packaging material and are not part of the upload list. Never upload private source code, databases, backups, deployment logs, credentials, or owner-only files. The archive itself becomes public as soon as it is committed, before the workflow can inspect it; run the local audit **before** upload.

## Reviewed deployment permissions

The workflow only runs on `main` in the exact new public repository. It runs on a manual request or a push changing the archive, manifest, verifier, or workflow. Pushes can therefore publish automatically after setup. It has no PR, schedule, or external dispatch trigger.

The audit job has repository-content **read** permission and uses a standard Ubuntu runner. It does not save a Git credential. The separate deployment job has only **Pages write** and **OIDC identity-token write** permission; it does not check out the repository or execute a custom script. GitHub supplies a short-lived token for this repository. No personal access token, repository-content write permission, Cloudflare credential, private-repository access, or account-wide grant is needed. Protect the `github-pages` environment so only `main` can deploy.

Both jobs have a 10-minute limit. Only the extracted website is uploaded as a Pages artifact, with one-day retention. There is no package installation, cache, paid/larger runner, or additional artifact. The official actions are pinned to full verified commit hashes. Update those pins only after reviewing an official release.

Standard GitHub-hosted compute for public repositories and Pages is free; larger runners are not. Artifact storage is subject to account allowances. A small archive and one-day retention minimize usage but are not a billing guarantee. Before enabling, verify the account has no payment method or an appropriate enforced stop-spend setting. Do not add billing or a paid runner. See [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and [included usage](https://docs.github.com/en/billing/reference/product-usage-included).

## Archive contract

`public-manifest.json` has exactly this shape:

```json
{
  "format": "portfolio-public-pages-v1",
  "basePath": "/portfolio-public/",
  "origin": "https://masudrabbani.github.io",
  "archiveSha256": "lowercase SHA-256 of the exact ZIP bytes",
  "files": [
    { "path": "index.html", "bytes": 123, "sha256": "lowercase SHA-256 of file bytes" }
  ]
}
```

Use file entries only, sorted by path for readable review; ZIP directory entries are unnecessary and rejected. Use ZIP stored/deflate compression, no comments, extra fields, symlinks, encryption, or ZIP64. Limits are 5,000 files, 32 MiB compressed, 128 MiB expanded total, 25 MiB per file, and a maximum 200:1 per-file compression ratio.

Paths must be relative ASCII public filenames without traversal, encoding tricks, duplicate/case-colliding names, private/API/admin/source paths, or unsupported extensions. The only hidden file allowed is an empty root `.nojekyll`. It is unnecessary in the custom Actions artifact because no Jekyll build occurs. `CNAME` and hosting configuration files are forbidden. Known secret, private-path, source-map, and live-analytics markers are rejected, but this scan cannot prove that arbitrary content is safe to publish. The reviewed public export remains the primary privacy boundary.

All hashes, sizes, inventory, file types, and preview policies are checked before `_site` is created. HTML must retain the preview no-index policy, any canonical links must remain on the live website, and local page resources must exist under `/portfolio-public/`. `robots.txt` must deny crawling. These preview rules intentionally leave live indexing and analytics unchanged; remove them only in a separately reviewed final migration.

## Local checks

From this directory, run:

```sh
python3 -I -m unittest discover -s tests -v
python3 -I verify_public_site.py
```

The second command requires the completed archive and manifest. It refuses an existing `_site` and never overwrites files. Test with a fresh disposable copy rather than deleting a user's existing output. No command makes a network request.

After the owner approves setup and publication, test the resulting preview on desktop and mobile: homepage, direct deep links, publications, blog, portraits, CSS/JavaScript, documents, RSS, 404 behavior, and the link to the separately authenticated owner portal. Confirm no admin/API content or credentials are served by Pages, no live analytics requests are made, and the live domain remains unchanged.

## Verified official action releases

- [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1): `3d3c42e5aac5ba805825da76410c181273ba90b1`
- [upload-pages-artifact v5.0.0](https://github.com/actions/upload-pages-artifact/releases/tag/v5.0.0): `fc324d3547104276b827a68afc52ff2a11cc49c9`
- [deploy-pages v5.0.1](https://github.com/actions/deploy-pages/releases/tag/v5.0.1): `368f82528645a54fb793d4d04e342629a3f51346`

The upload action's reviewed manifest also pins its nested upload-artifact dependency. For setup details, see [custom Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
