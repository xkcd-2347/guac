# Red Hat Guac

This repository holds the Red Hat fork of
`trustification/guac` with modifications needed only for Red Hat.

## Mirroring upstream

### Mirroring HEAD from upstream `main`

The HEAD of the upstream repo, `trustification/guac` is mirrored on the
`release-next` and `release-next-ci` branches using the [`redhat/release/update-to-head.sh`](redhat/release/update-to-head.sh) script. When this script is run without any arguments, the following steps are taken.

- The upstream HEAD is fetched and checked out as the `release-next` branch
- The `origin` remote `main` branch is pulled and Red-Hat-specific files from that branch are applied to the `release-next` branch
- The `release-next` branch is force pushed to the `origin` remote
- The `release-next` branch is duplicated to `release-next-ci`
- A timestamp file is added to `release-next-ci` branch
- The `release-next-ci` branch is force pushed to the `origin` remote
- A pull request is created (if it does not already exist) for this change, to trigger a CI run
- OpenShift CI runs the upstream unit and integration tests on the PR

## Local configuration

To use this script locally, you'll need to have two git remotes for this repository.

- `upstream` pointing to `trustification/guac`
- `origin` pointing to `sguacsec/guac` (this repo)