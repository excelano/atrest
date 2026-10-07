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

// keyStore is one place a keyedAESGCM key can live. key returns name's key:
// an existing one, or with create a fresh one stored under name. It returns
// errUnavailable when the store cannot be reached or is locked, and errNoKey
// when it is reachable but holds nothing under name and create is false.
type keyStore interface {
	id() string
	key(name string, create bool) ([]byte, error)
}

// keyedAESGCM protects data with AES-256-GCM under a 32-byte key, one per
// name, kept in the first of its stores that is reachable when sealing. The
// construction is the same on Linux and macOS; what differs between them is
// which stores there are.
type keyedAESGCM struct {
	stores []keyStore
}

func (p keyedAESGCM) alg() string { return "aes-gcm" }

func (p keyedAESGCM) protect(name string, plain []byte) ([]byte, string, error) {
	for _, s := range p.stores {
		key, err := s.key(name, true)
		if errors.Is(err, errUnavailable) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		sealed, err := sealWith(key, plain)
		return sealed, s.id(), err
	}
	return nil, "", errUnavailable
}

// unprotect asks the store the envelope names for name's key, and reports a
// store it cannot reach as locked rather than manufacturing a key that would
// fail to verify. An envelope from before stores were recorded names none, so
// every reachable store that holds a key under name is tried in turn.
func (p keyedAESGCM) unprotect(name, store string, sealed []byte) ([]byte, error) {
	if store == "" {
		for _, s := range p.stores {
			key, err := s.key(name, false)
			if err != nil {
				continue
			}
			if plain, err := openWith(key, sealed); err == nil {
				return plain, nil
			}
		}
		return nil, errors.New("no reachable key store holds its key")
	}
	s := p.store(store)
	if s == nil {
		return nil, fmt.Errorf("unknown key store %q", store)
	}
	key, err := s.key(name, false)
	if errors.Is(err, errUnavailable) {
		return nil, lockedError{store: s.id()}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.id(), err)
	}
	return openWith(key, sealed)
}

func (p keyedAESGCM) store(id string) keyStore {
	for _, s := range p.stores {
		if s.id() == id {
			return s
		}
	}
	return nil
}

func sealWith(key, plain []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating a nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func openWith(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed data shorter than a nonce")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// randomKey is a fresh AES-256 key for a store that holds nothing under a
// name and has been asked to create one.
func randomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating a key: %w", err)
	}
	return key, nil
}
