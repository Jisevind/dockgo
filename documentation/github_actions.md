# GitHub Actions Release Flow

When you push code to the `main` or `master` branch in this repository, it triggers the `.github/workflows/release.yml` GitHub Action. This workflow automates the entirely of your versioning and release process.

Here is exactly what happens step-by-step during that workflow:

## 1. Semantic Version Analysis

First, the workflow checks out your code and runs **Semantic Release**. This tool analyzes all the commit messages you've made since the last release utilizing the Conventional Commits specification.

*   Depending on your commit prefixes (e.g., `feat:`, `fix:`, `BREAKING CHANGE`), it automatically calculates what the next version number should be.
*   If your commits don't warrant a major, minor, or patch release (for example, if you only pushed `chore:` or `docs:` commits), **the workflow stops here safely** without doing anything else.

## 2. GitHub Release Creation

If a new release *is* warranted, Semantic Release will automatically perform the following steps:

*   Generate a detailed, formatted Changelog based on your recent commit messages.
*   Push a new git tag to your repository branch (like `v1.2.0`).
*   Publish an official "GitHub Release" on your repository page, attaching the Changelog.

## 3. Docker Image Build & Publish (GHCR)

If (and only if) a new version was successfully evaluated and published in the step above, the workflow moves on to the Docker steps:

*   **Setup & Auth**: It sets up Docker Buildx and logs securely into the GitHub Container Registry (`ghcr.io`) using the repository's native `GITHUB_TOKEN`.
*   **Build**: It builds your Docker image from the `Dockerfile`, passing the freshly generated version number in as the `VERSION` build argument (so your backend Go server is aware of its own version).
*   **Publish**: Finally, it pushes the built image to your GitHub Container Registry twice:
    *   Tagged with the specific new version (e.g., `ghcr.io/your-username/dockgo:1.2.0`)
    *   Tagged as the active latest build (e.g., `ghcr.io/your-username/dockgo:latest`)

## Summary

In short: **You never have to manually version or publish your app.** As long as you merge code into `main` using standard conventional commits (`feat: add something`, `fix: repair something`), GitHub Actions will automatically tag the release, generate the changelog, build the Docker image, and publish it ready for users to pull!
