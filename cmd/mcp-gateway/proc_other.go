//go:build !linux

package main

// processStartToken has no cheap, dependency-free answer outside Linux, so
// a pid is rung on its own there (design/adr/0044, "O que não resolve").
func processStartToken(int) string { return "" }
