// Package repogate holds the repository's cross-cutting gates as Go tests,
// run by `go test ./...` in CI like any other package. It carries one
// enforcement file (ported from the retired host-python test suite):
//
//   - boundary_test.go — DX_DFIR must not house what Byakugan owns: the
//     engine's reference docs stay in the Byakugan repo, everything the
//     engine writes into data_store/ stays un-commit-able (deny-by-default
//     gitignore, skeleton-only tracking), the lane roles' out-dir defaults
//     stay under data_store/processed/, the engine pin stays a full sha —
//     and the host-python package itself stays retired.
//
// Contract-fit (a lane's run spec matching its tool contract) is now the
// get_sybers.godfir_run collection's concern — it ships each contract and
// validates the run spec against it, covered by that collection's own tests.
package repogate
