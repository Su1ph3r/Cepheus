# Homebrew formula for Cepheus.
#
# Install:
#   brew tap su1ph3r/cepheus https://github.com/Su1ph3r/Cepheus
#   brew install cepheus
#
# The formula downloads the prebuilt darwin binary attached to the
# GitHub Release rather than the Python sdist + dependency tree — keeps
# `brew install cepheus` fast and avoids dragging in a full Python
# stack just for the CLI.
#
# When bumping the version:
#   1. Update `version` to match pyproject.toml.
#   2. Update `url` paths for both architectures to the new release tag.
#   3. Update `sha256` values from the SHA256SUMS file attached to the
#      release (release.yml computes these automatically).
#   4. Commit alongside the version bump so `brew tap` users see the
#      new version on `brew update`.
#
# Skip steps 2-3 entirely by deleting this file's sha256 lines and
# letting Homebrew prompt for fresh hashes — easier during initial
# development, mandatory for published taps.

class Cepheus < Formula
  desc "Container Escape Scenario Modeler — enumerate posture, verify primitives"
  homepage "https://github.com/Su1ph3r/Cepheus"
  version "0.4.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/Su1ph3r/Cepheus/releases/download/v#{version}/cepheus-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/Su1ph3r/Cepheus/releases/download/v#{version}/cepheus-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Su1ph3r/Cepheus/releases/download/v#{version}/cepheus-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/Su1ph3r/Cepheus/releases/download/v#{version}/cepheus-linux-amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    # Nuitka emits a single self-extracting binary; just rename and drop
    # it into Homebrew's bin/ prefix. Strip the platform suffix from the
    # downloaded asset so the installed name matches `cepheus`.
    bin.install Dir["cepheus-*"].first => "cepheus"
  end

  test do
    # Smoke test: --version exits 0 and prints a semver-shaped string.
    assert_match version.to_s, shell_output("#{bin}/cepheus --version")
  end
end
