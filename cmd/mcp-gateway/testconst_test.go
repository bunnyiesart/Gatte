package main

// Test constants shared across build variants. These must stay in an
// untagged file: admin_manage_test.go (no build tag) and ui_manage_test.go
// (//go:build !nofront) both reference them, so the nofront build needs them
// too.

// uiSecretMarker is a vault value no page may ever carry.
const uiSecretMarker = "ui-secret-marker-5f1c-not-real"
