// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux

package atrest

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// secretServiceStore keeps keys as items in the login keyring's default
// collection, over the user's own D-Bus session bus. It is unavailable when
// there is no session bus, no Secret Service listening on it, or the default
// collection is locked and unlocking it would need a prompt a key lookup
// cannot show; unlockSecretService is what shows one.
//
// The session between this store and the service carries the key in the
// clear, over "plain" algorithm negotiation rather than the spec's optional
// Diffie-Hellman one: the bus is a Unix socket only the calling user can
// connect to, so encrypting a hop that never leaves the kernel buys nothing.
type secretServiceStore struct{}

func (secretServiceStore) id() string { return "secret-service" }

func (secretServiceStore) key(name string, create bool) ([]byte, error) {
	conn, err := sessionBus()
	if err != nil {
		return nil, errUnavailable
	}
	defer conn.Close()

	service := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := service.Call(secretServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return nil, errUnavailable
	}
	defer conn.Object("org.freedesktop.secrets", session).Call(secretSessionIface+".Close", 0)

	collection := conn.Object("org.freedesktop.secrets", defaultCollectionPath)
	attrs := map[string]string{secretAttrName: name}

	var items []dbus.ObjectPath
	if err := collection.Call(secretCollectionIface+".SearchItems", 0, attrs).Store(&items); err != nil {
		return nil, errUnavailable
	}
	if len(items) > 0 {
		var got secretValue
		item := conn.Object("org.freedesktop.secrets", items[0])
		if err := item.Call(secretItemIface+".GetSecret", 0, session).Store(&got); err != nil {
			return nil, errUnavailable
		}
		return got.Value, nil
	}
	if !create {
		if !collectionUnlocked(conn) {
			return nil, errUnavailable
		}
		return nil, errNoKey
	}

	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	props := map[string]dbus.Variant{
		secretItemIface + ".Label":      dbus.MakeVariant("atrest: " + name),
		secretItemIface + ".Attributes": dbus.MakeVariant(attrs),
	}
	secret := secretValue{Session: session, Value: key, ContentType: "application/octet-stream"}
	var item, prompt dbus.ObjectPath
	if err := collection.Call(secretCollectionIface+".CreateItem", 0, props, secret, true).Store(&item, &prompt); err != nil {
		return nil, errUnavailable
	}
	if item == "" || item == "/" {
		// A prompt path with no item means the collection needs unlocking
		// through a UI this call has no way to show.
		return nil, errUnavailable
	}
	return key, nil
}

// secretServiceUnlocked reports whether the default collection exists and is
// unlocked, which is when the store can return a key instead of
// errUnavailable. It creates nothing.
func secretServiceUnlocked() bool {
	conn, err := sessionBus()
	if err != nil {
		return false
	}
	defer conn.Close()
	return collectionUnlocked(conn)
}

func collectionUnlocked(conn *dbus.Conn) bool {
	locked, err := conn.Object("org.freedesktop.secrets", defaultCollectionPath).GetProperty(secretCollectionIface + ".Locked")
	return err == nil && locked.Value() == false
}

// unlockSecretService asks the service to unlock the default collection and,
// when that needs the user's password, shows the prompt the service provides
// for it and waits for the answer. The prompt is a window on the user's
// display, so a process with none — an SSH session, a cron job — is told so
// instead of leaving a dialog nobody can see. That check comes before the
// service is asked for a prompt, because gnome-keyring-daemon aborts when a
// prompt it has created is dismissed without ever having been shown.
func unlockSecretService(ctx context.Context) error {
	conn, err := sessionBus()
	if err != nil {
		return fmt.Errorf("atrest: unlocking: no session bus: %w", err)
	}
	defer conn.Close()
	if collectionUnlocked(conn) {
		return nil
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("atrest: unlocking: no display to show the keyring's prompt on")
	}

	service := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := service.Call(secretServiceIface+".Unlock", 0, []dbus.ObjectPath{defaultCollectionPath}).Store(&unlocked, &prompt); err != nil {
		return fmt.Errorf("atrest: unlocking: %w", err)
	}
	if prompt == "/" {
		return nil
	}

	// Subscribe before prompting so the answer cannot arrive unheard.
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(prompt), dbus.WithMatchInterface(secretPromptIface), dbus.WithMatchMember("Completed")); err != nil {
		return fmt.Errorf("atrest: unlocking: %w", err)
	}
	completed := make(chan *dbus.Signal, 4)
	conn.Signal(completed)
	prompter := conn.Object("org.freedesktop.secrets", prompt)
	if err := prompter.Call(secretPromptIface+".Prompt", 0, "").Err; err != nil {
		return fmt.Errorf("atrest: unlocking: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			prompter.Call(secretPromptIface+".Dismiss", 0)
			return fmt.Errorf("atrest: unlocking: %w", ctx.Err())
		case sig := <-completed:
			if sig.Path != prompt || len(sig.Body) < 1 {
				continue
			}
			if dismissed, _ := sig.Body[0].(bool); dismissed {
				return errors.New("atrest: unlocking: the prompt was dismissed")
			}
			return nil
		}
	}
}

func sessionBus() (*dbus.Conn, error) {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, err
	}
	if err := conn.Auth(nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

const (
	secretServiceIface    = "org.freedesktop.Secret.Service"
	secretSessionIface    = "org.freedesktop.Secret.Session"
	secretCollectionIface = "org.freedesktop.Secret.Collection"
	secretItemIface       = "org.freedesktop.Secret.Item"
	secretPromptIface     = "org.freedesktop.Secret.Prompt"
	secretAttrName        = "atrest-name"
)

// defaultCollectionPath is the login keyring every desktop session already
// keeps unlocked, addressed by its alias so this works whether or not the
// user renamed the collection itself.
const defaultCollectionPath = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")

// secretValue is the Secret Service "Secret" structure: a session, the
// algorithm-specific parameters (empty under "plain"), the value, and its
// content type. Field order is the wire order; godbus reads a Go struct's
// fields as a D-Bus struct in the order they are declared.
type secretValue struct {
	Session     dbus.ObjectPath
	Params      []byte
	Value       []byte
	ContentType string
}
