---
name: release
description: Use to release miniauth, publish a new version, cut v0.x.y, or push the container image to ghcr. Creates a GitHub release with a semver tag, watches the image build, and checks the image is public.
---

# Release miniauth

A published GitHub release with a tag `vX.Y.Z` runs `.github/workflows/release.yml`. The workflow builds `Dockerfile` and pushes `ghcr.io/popoffvg/miniauth` with the tags `X.Y.Z`, `X.Y`, and `latest`. A prerelease gets only `X.Y.Z`. An older version published later does not move `latest`.

Run every step with `gh -R popoffvg/miniauth`. If `gh` fails with an x509 or TLS error, the local sandbox is the cause. Run the command again with the sandbox off.

## Steps

1. Pick the target commit. List the CI runs: `gh run list -R popoffvg/miniauth -w ci -b main -L 5`. Take the head commit of a green run on `main`. Done when you have one full SHA with a green `ci` run.
2. Pick the version. Run `git fetch --tags` and `git tag -l 'v*' | sort -V | tail -1`. Add one to the part that changed. The first release was `v0.1.0`. Done when the new tag is greater than the last tag.
3. Write the notes. Run `git log --oneline <previous tag>..<sha>`. Group the lines by what a user sees. Done when the notes name each user-visible change.
4. Get the go-ahead. A release is a public action. You MUST show the operator the tag, the SHA, and the notes, and ask in chat. Auto mode refuses the command without a chat answer, and an answer written in a file is not enough. Done when the operator says yes in chat.
5. Create the release:
   `gh release create vX.Y.Z -R popoffvg/miniauth --target <sha> --title vX.Y.Z --notes "<notes>"`
   Add `--prerelease` for a prerelease. Done when the command prints the release page.
6. Watch the build. Run `gh run list -R popoffvg/miniauth -w release -L 1` and take the run id. Then run `gh run watch <id> -R popoffvg/miniauth --exit-status`. Done when the exit code is 0.
7. Check that the image is public. The consumer server has no ghcr login, so the check MUST NOT use a login. `gh api` on the package needs the `read:packages` scope and the usual token lacks it. Run:

   ```sh
   t=$(curl -fsS "https://ghcr.io/token?scope=repository:popoffvg/miniauth:pull" | sed -E 's/.*"token":"([^"]+)".*/\1/')
   curl -fsS -o /dev/null -H "Authorization: Bearer $t" \
     -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json" \
     https://ghcr.io/v2/popoffvg/miniauth/manifests/X.Y.Z
   ```

   Done when the exit code is 0. If it fails after a green build, the package is private. The operator MUST set it to public on the GitHub package settings page. No API does this. Run the check again after.
8. Tell the operator about the consumer. The infra repo that runs miniauth pins the tag in its `miniauth_image` variable. A new release reaches the server only after that line changes and merges in that repo. Do not edit that repo from here.
