// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build !windows && !linux && !darwin

package atrest

// platform is nil where atrest has no facility yet, and Seal passes data
// through unchanged.
var platform protector
