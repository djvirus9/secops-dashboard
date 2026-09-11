# Release images and verification

The image workflow publishes these Linux amd64/arm64 images:

- `ghcr.io/djvirus9/secops-dashboard-backend` (backend and both worker services)
- `ghcr.io/djvirus9/secops-dashboard-frontend` (Node 24 LTS)

Use the digest references attached to a completed GitHub release, not a staging
build tag. `infra/docker-compose.images.yml` has no build steps; it shares runtime
configuration with source mode and pulls the specified images. Copy the two
`BACKEND_IMAGE=...@sha256:...` and `FRONTEND_IMAGE=...@sha256:...` lines from the
release's `release-images.env` into your private `.env`. Do not replace your secrets
or database settings with that artifact.

Digests identify immutable image contents. The workflow refuses to replace an
existing `vMAJOR.MINOR.PATCH` tag and publishes no moving `latest` tag. Registry
administrators can still retag packages outside this workflow, which is why the
deployment instructions use digests. Public package availability and the final
digest pair must be verified before announcing a release.

## Maintainer publication

1. Update Python and frontend version metadata together and complete the changelog.
   Merge through the required PR checks. Wait for the exact new main commit's
   **CI** and **CodeQL** push runs to succeed, including all required job names.
2. Run **Publish release images** manually from `main`, entering the stable version
   (for example `v0.3.0`) and full current main SHA. The gate verifies the branch,
   manifest versions, latest post-merge workflow/job outcomes and unused version
   tags. It rechecks these conditions before promotion. Do not dispatch from a tag
   or feature branch. Ordinary PR CI has no package-write permissions.
3. The workflow builds both architectures under unique staging tags, includes
   BuildKit SBOM/provenance metadata and GitHub build attestations, and tests the
   actual image digests on native amd64 and arm64 runners. Each disposable stack
   verifies authentication, origin checks, scoped ingestion/revocation, an idle
   GitHub worker, persistence and backup/restore. No real integration token is used.
4. Only after those checks pass does the workflow assign version tags to the
   tested image indexes. It verifies the tagged digests match and uploads
   `release-images.env` as artifact `release-images-vMAJOR.MINOR.PATCH`.
5. After first publication, check both GHCR package settings and set visibility to
   **Public** if needed. GitHub's initial package visibility is private even for a
   public source repository. Verify anonymous pulls of both digests and inspect
   their amd64/arm64 manifests. Do not claim public images while pulls need credentials.
6. Download the digest artifact, verify provenance, and attach it to the GitHub
   release for the same tested commit. Include upgrade/backup guidance. Publishing
   images does not automatically tag source, create a GitHub release or deploy a server.

For example, verify a release digest with the GitHub CLI, substituting the real
published digest and repeating for the frontend:

```bash
gh attestation verify oci://ghcr.io/djvirus9/secops-dashboard-backend@sha256:ACTUAL_DIGEST -R djvirus9/secops-dashboard
docker buildx imagetools inspect ghcr.io/djvirus9/secops-dashboard-backend@sha256:ACTUAL_DIGEST
```

BuildKit stores per-platform SBOM and provenance in the image index; inspect them
with Buildx's `--format '{{json .SBOM}}'` and `--format '{{json .Provenance}}'`
options. GitHub build attestations establish the publishing workflow's provenance;
neither provenance nor an SBOM proves that an image has no vulnerabilities.

If a build or smoke check fails, the version tags remain unused and a new workflow
attempt can rebuild staging images. If promotion partially succeeds or an upload
fails after tagging, the gate deliberately refuses to overwrite the existing tag.
Inspect the successful build digests and native smoke runs before completing any
missing release artifact; do not delete/retag a published version to bypass a gate.
If main advances before promotion, publish only after the new main's checks pass.

The workflow follows Docker's [multi-platform image guidance](https://docs.docker.com/build/ci/github-actions/multi-platform/)
and [SBOM/provenance support](https://docs.docker.com/build/ci/github-actions/attestations/),
plus GitHub's [container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [artifact attestation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
documentation.
