# Installing Cepheus

Cepheus ships in five forms so it fits whatever environment you're
trying to run it in. Pick the one closest to your situation:

| Form | Best for | Setup |
|---|---|---|
| **`pip`** | Existing Python environments, CI runners with Python already installed | [pip](#pip) |
| **Native binary** | Air-gapped hosts, distroless / minimal CI runners, "I just want one file" | [Binary](#native-binary) |
| **Container** | CI workflows, ephemeral scans without polluting the host | [Container](#container-ghcr) |
| **Homebrew** | macOS + Linux developer workstations | [Homebrew](#homebrew-macos--linux) |
| **Scoop** | Windows developer workstations | [Scoop](#scoop-windows) |
| **From source** | Contributors, downstream packagers | [Source](#from-source) |

The features and behaviour are identical across all five paths — the
underlying tool is the same Python codebase, just distributed
differently.

---

## pip

```sh
pip install cepheus      # once published to PyPI
# until then:
pip install git+https://github.com/Su1ph3r/Cepheus@v0.4.1
# or grab the wheel from the release page:
pip install https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-0.4.1-py3-none-any.whl
```

Optional extras:

```sh
pip install 'cepheus[html]'         # HTML report generator (jinja2)
pip install 'cepheus[llm]'          # LLM enrichment via litellm
pip install 'cepheus[html,llm]'     # both
```

Requires Python 3.11 or newer.

---

## Native binary

Single self-contained binaries for the major platforms — no Python
runtime required. Built with Nuitka, sha256-verified.

```sh
# Linux amd64
curl -L -o cepheus \
  https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-linux-amd64
chmod +x cepheus
./cepheus --version

# Linux arm64
curl -L -o cepheus \
  https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-linux-arm64

# macOS Intel
curl -L -o cepheus \
  https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-darwin-amd64

# macOS Apple Silicon
curl -L -o cepheus \
  https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-darwin-arm64

# Windows amd64 (PowerShell)
Invoke-WebRequest `
  -Uri https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/cepheus-windows-amd64.exe `
  -OutFile cepheus.exe
```

Verify with the published SHA-256 checksums:

```sh
curl -L -o SHA256SUMS \
  https://github.com/Su1ph3r/Cepheus/releases/download/v0.4.1/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

---

## Container (GHCR)

Multi-arch image (`linux/amd64` + `linux/arm64`) published on every
release. Tagged `:X.Y.Z`, `:X.Y`, and `:latest`.

### One-off scan of an image

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/su1ph3r/cepheus:0.4.1 \
  ci nginx:latest --max-severity critical --format sarif --output /dev/stdout
```

The docker socket bind-mount is what lets Cepheus shell out to `docker
run --rm <image> ...` to spin up an ephemeral enumeration container.
Without it, `cepheus ci` falls back to posture-file mode only.

### Scan a posture file (no docker socket needed)

```sh
docker run --rm \
  -v "$PWD:/work" -w /work \
  ghcr.io/su1ph3r/cepheus:0.4.1 \
  ci posture.json --max-severity critical --format sarif -o report.sarif
```

### Verify a running container against itself

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/su1ph3r/cepheus:0.4.1 \
  verify --container-id my-running-container --format sarif --output /dev/stdout
```

### Image tags

| Tag | Use case |
|---|---|
| `ghcr.io/su1ph3r/cepheus:0.4.1` | Pin to an exact version (recommended for CI) |
| `ghcr.io/su1ph3r/cepheus:0.4` | Track the latest patch in a minor line |
| `ghcr.io/su1ph3r/cepheus:latest` | Track the latest stable release (avoid in CI) |

The image runs as a non-root user `cepheus` (uid 1000) by default;
override with `--user 0:0` if the docker-socket bind-mount needs
root permissions on the host.

---

## Homebrew (macOS + Linux)

```sh
brew tap su1ph3r/cepheus https://github.com/Su1ph3r/Cepheus
brew install cepheus
cepheus --version
```

The formula downloads the prebuilt darwin/linux binary for your
architecture, so `brew install cepheus` is faster than a from-source
install. The formula lives in this repo at `Formula/cepheus.rb`.

Upgrade:

```sh
brew update && brew upgrade cepheus
```

---

## Scoop (Windows)

```powershell
scoop install https://raw.githubusercontent.com/Su1ph3r/Cepheus/main/scoop/cepheus.json
cepheus --version
```

For repeatable installs, add the bucket once:

```powershell
scoop bucket add cepheus https://github.com/Su1ph3r/Cepheus
scoop install cepheus/cepheus
```

The manifest auto-updates against new GitHub releases via Scoop's
`checkver` + `autoupdate` mechanism — `scoop update cepheus` always
fetches the latest version.

---

## From source

```sh
git clone https://github.com/Su1ph3r/Cepheus.git
cd Cepheus
pip install -e '.[dev,html,llm]'
pytest
cepheus --version
```

To build the same artifacts the release workflow produces:

```sh
# sdist + wheel
python -m build

# single-binary via Nuitka (slow — 5-10 min)
pip install 'nuitka>=2.4,<3.0'
python -m nuitka \
  --standalone --onefile --assume-yes-for-downloads --lto=yes \
  --enable-plugin=anti-bloat \
  --include-package=cepheus --include-package-data=cepheus \
  --output-filename=cepheus \
  src/cepheus/__main__.py
```

---

## Air-gapped / offline install

Download the wheel and all dependency wheels on a host with internet
access:

```sh
mkdir cepheus-offline
pip download --dest cepheus-offline cepheus      # or use the GitHub release wheel
```

Transfer the directory to the air-gapped host and install:

```sh
pip install --no-index --find-links cepheus-offline cepheus
```

Or skip Python entirely: download the appropriate native binary from
the release page and `chmod +x` it.
