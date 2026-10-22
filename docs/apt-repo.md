# Installing from the apt repository

The GitHub Actions workflow (`.github/workflows/deb.yml`) builds the package in a Debian 13 container on every push and pull request and uploads it as a workflow artifact (`server-hands-deb`, plus `SHA256SUMS`; `hands-client-linux-amd64` is the test client). Pushing a tag `v*` (for example `v0.5.0`) additionally publishes the package to a signed apt repository served from GitHub Pages, so the server can install and upgrade it with plain `apt`.

## Install on the server

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://mblcdr.github.io/Server-Hands/server-hands.gpg | sudo tee /etc/apt/keyrings/server-hands.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/server-hands.gpg] https://mblcdr.github.io/Server-Hands/ ./" | sudo tee /etc/apt/sources.list.d/server-hands.list
sudo apt update && sudo apt install server-hands
```

Later updates are `sudo apt update && sudo apt upgrade`. The package never enables the service by itself (see `homelab-setup.md`), and upgrades keep `/etc/server-hands/config.toml` (it is a conffile).

Before trusting the key, compare its fingerprint with the one you recorded when you generated it:
`gpg --show-keys --with-fingerprint /etc/apt/keyrings/server-hands.gpg`. The key is fetched over HTTPS from the same host as the packages, so the fingerprint check is what protects the first install.

## One-time setup (repository owner)

1. **Signing key.** A dedicated key used only for this repository:
   ```sh
   export GNUPGHOME=$(mktemp -d)
   gpg --batch --passphrase '' --quick-generate-key "Server Hands apt <you@example.com>" ed25519 sign 5y
   gpg --list-keys --with-fingerprint            # write the fingerprint down (README, password manager)
   gpg --armor --export-secret-keys "Server Hands apt" > /tmp/apt-signing-key.asc
   ```
   Store the private key only as a repository secret, then delete the file and the temporary `GNUPGHOME`.
2. **Secrets** (GitHub: Settings, Secrets and variables, Actions): `APT_GPG_PRIVATE_KEY` = the contents of `apt-signing-key.asc`. Add `APT_GPG_PASSPHRASE` only if you gave the key a passphrase.
3. **Pages.** Settings, Pages, Source: "Deploy from a branch", branch `gh-pages`, folder `/ (root)`. The branch is created by the first publish; if the Pages setting is not selectable yet, run step 4 first and then set it.
4. **First release.** `git tag v0.5.0 && git push origin v0.5.0`. Wait for the `publish` job, then open `https://mblcdr.github.io/Server-Hands/`.

The tag name becomes the package version (`v0.5.0` gives `0.5.0`), so tag in increasing order; apt only upgrades to a higher version. Builds from `main` get versions like `0.5.0+git42.abc1234` and are artifacts only, never published unless you run the workflow manually with "publish" ticked.

Rotating the key: generate a new one, update the secret, publish a release, and tell users to replace `/etc/apt/keyrings/server-hands.gpg`. The key expires after five years as created above; extend it with `gpg --quick-set-expire` before then and update the secret.

## Notes

- amd64 only. An arm64 build needs a second job on an `ubuntu-24.04-arm` runner (free for public repositories).
- Third-party actions are referenced by major version tag. Pin them to commit SHAs if you want protection against a compromised tag; the publish job holds the signing key, so that is the part worth pinning first.
- The repository is "flat" (`deb ... ./`), so there is no `dists/` tree and no codename to choose.
