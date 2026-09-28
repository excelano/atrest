// Author: David M. Anderson
// Built with AI assistance (Claude, Anthropic)

//go:build linux

package atrest

import (
	"github.com/godbus/dbus/v5"
)

// secretServiceKey fetches or creates name's key as an item in the login
// keyring's default collection, over the user's own D-Bus session bus. It
// returns errUnavailable when there is no session bus, no Secret Service
// listening on it, or the default collection is locked and unlocking it would
// need a prompt this call cannot show.
//
// The session between this call and the service carries the key in the
// clear, over "plain" algorithm negotiation rather than the spec's optional
// Diffie-Hellman one: the bus is a Unix socket only the calling user can
// connect to, so encrypting a hop that never leaves the kernel buys nothing.
func secretServiceKey(name string) ([]byte, error) {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, errUnavailable
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return nil, errUnavailable
	}
	if err := conn.Hello(); err != nil {
		return nil, errUnavailable
	}

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

const (
	secretServiceIface    = "org.freedesktop.Secret.Service"
	secretSessionIface    = "org.freedesktop.Secret.Session"
	secretCollectionIface = "org.freedesktop.Secret.Collection"
	secretItemIface       = "org.freedesktop.Secret.Item"
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
