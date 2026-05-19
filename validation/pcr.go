package validation

import (
	"path/filepath"
	"runtime"

	oavalidation "github.com/cloudx-io/openauction/validation"
)

// DefaultPCRConfigPath returns the path to the pcrs.json file shipped
// alongside this package.
func DefaultPCRConfigPath() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "pcrs.json")
}

// LoadPCRsFromFile reads a PCR config file and returns the listed sets.
// It delegates to cloudx-io/openauction/validation; the schema is
// shared.
func LoadPCRsFromFile(path string) ([]PCRSet, error) {
	return oavalidation.LoadPCRsFromFile(path)
}
