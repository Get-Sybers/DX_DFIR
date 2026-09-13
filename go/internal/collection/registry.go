package collection

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo)
)

// registryPath is data_store/raw/collections/.registry.db.
func registryPath(repoRoot string) string {
	return filepath.Join(collectionsRoot(repoRoot), registryName)
}

// registry holds the authoritative bits the DB owns: which names are registered
// and which one is selected. Read from the SQLite file WITHOUT creating it — a
// pure read must never mutate the store, so a missing DB is simply "empty".
type registry struct {
	names    []string        // registered names, alpha-sorted
	nameSet  map[string]bool // membership
	selected string          // active collection, "" if none
}

// readRegistry opens .registry.db read-only and loads the registered names and
// the selected one. A missing DB (nothing registered yet) is not an error.
func readRegistry(repoRoot string) (*registry, error) {
	reg := &registry{nameSet: map[string]bool{}}
	path := registryPath(repoRoot)
	if _, err := os.Stat(path); err != nil {
		return reg, nil // no DB => nothing registered; leave filesystem probes to the caller
	}
	// mode=ro: never create or write; immutable would be wrong (a concurrent
	// writer may hold it), plain read-only is the faithful, safe choice.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return reg, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, selected FROM collections ORDER BY name")
	if err != nil {
		return reg, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var selected int
		if err := rows.Scan(&name, &selected); err != nil {
			return reg, err
		}
		reg.names = append(reg.names, name)
		reg.nameSet[name] = true
		if selected != 0 {
			reg.selected = name
		}
	}
	return reg, rows.Err()
}
