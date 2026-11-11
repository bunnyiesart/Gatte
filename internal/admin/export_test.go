package admin

import "time"

// SetWazuhCheckTimeout shortens the indexer timeout for a test and returns
// the function that restores it.
func SetWazuhCheckTimeout(d time.Duration) (restore func()) {
	old := wazuhCheckTimeout
	wazuhCheckTimeout = d
	return func() { wazuhCheckTimeout = old }
}
