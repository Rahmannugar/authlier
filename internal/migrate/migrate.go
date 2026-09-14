package migrate

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

const separator = "-- authlier:split"

type Migration struct {
	Version string
	SQL     []string
}

func Read(files fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}
		statements := make([]string, 0)
		for _, statement := range strings.Split(string(body), separator) {
			if statement = strings.TrimSpace(statement); statement != "" {
				statements = append(statements, statement)
			}
		}
		if len(statements) == 0 {
			return nil, fmt.Errorf("migration %s has no statements", entry.Name())
		}
		migrations = append(migrations, Migration{Version: entry.Name(), SQL: statements})
	}
	return migrations, nil
}
