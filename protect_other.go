// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build !windows && !linux && !darwin

package atrest

import (
	"context"
	"errors"
)

// platform is nil where atrest has no facility yet, and Seal passes data
// through unchanged.
var platform protector

func persistent() bool { return false }

func unlock(context.Context) error { return errors.New("atrest: no key store to unlock") }
