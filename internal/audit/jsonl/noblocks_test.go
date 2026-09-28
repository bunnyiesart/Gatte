package jsonl_test

import "context"

// noBlocks is the blocklist of a gateway where nobody has been blocked
// (design/adr/0031). The Gateway requires one.
type noBlocks struct{}

func (noBlocks) Blocked(context.Context, string) (bool, error) { return false, nil }
