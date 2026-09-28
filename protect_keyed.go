// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux || darwin

package atrest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// keyedAESGCM protects data with AES-256-GCM under a 32-byte key that
// getOrCreateKey fetches or creates, one key per name. The construction is
// the same on Linux and macOS; what differs between them is where the key
// lives, which is all getOrCreateKey has to say.
type keyedAESGCM struct {
	getOrCreateKey func(name string) ([]byte, error)
}

func (p keyedAESGCM) alg() string { return "aes-gcm" }

func (p keyedAESGCM) protect(name string, plain []byte) ([]byte, error) {
	gcm, err := p.cipher(name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating a nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// unprotect asks for name's key the same way protect does. When sealed was
// written under a key this call cannot find, getOrCreateKey manufactures a
// fresh one instead of reporting it missing, and GCM's authentication tag
// then fails to verify against it — the same ErrCannotOpen a caller sees for
// any other cache it cannot open, with no separate "wrong key" case to carry.
func (p keyedAESGCM) unprotect(name string, sealed []byte) ([]byte, error) {
	gcm, err := p.cipher(name)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed data shorter than a nonce")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (p keyedAESGCM) cipher(name string) (cipher.AEAD, error) {
	key, err := p.getOrCreateKey(name)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randomKey is a fresh AES-256 key for a getOrCreateKey that found nothing to
// return instead.
func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating a key: %w", err)
	}
	return key, nil
}
