// Package repogate holds the repository's cross-cutting gates as Go tests,
// run by `go test ./...` in CI like any other package. They are the direct
// port of the retired host-python test suite's two enforcement files:
//
//   - boundary_test.go — DX_DFIR must not house what Byakugan owns: the
//     engine's reference docs stay in the Byakugan repo, everything the
//     engine writes into data_store/ stays un-commit-able (deny-by-default
//     gitignore, skeleton-only tracking), the lane roles' out-dir defaults
//     stay under data_store/processed/, the engine pin stays a full sha —
//     and the host-python package itself stays retired.
//
//   - contractfit_test.go — lane roles must fit the pinned GoDFIR-toolz
//     tool contracts: every env key a role sets and every container path it
//     mounts exists at the submodule pin, and every required mount is
//     bound. A role and the submodule gitlink can only move together.
package repogate
