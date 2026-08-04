package bundle

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/pythonhk/eventctl/internal/identity"
)

func TestAuthenticatePublicVerifiesOuterSignature(t *testing.T) {
	fixture := newCryptoFixture(t)
	path := makeValidBundle(t, fixture)
	public := identity.Public{
		Algorithm: identity.Algorithm, KeyID: identity.KeyID(fixture.publicKey),
		PublicKey: base64.RawURLEncoding.EncodeToString(fixture.publicKey),
	}
	inspection, err := AuthenticatePublic(context.Background(), path, public, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Envelope.KeyID != public.KeyID || inspection.BundleSHA256 == "" {
		t.Fatalf("AuthenticatePublic() returned incomplete result: %#v", inspection)
	}

	wrong := newCryptoFixture(t)
	wrongPublic := identity.Public{
		Algorithm: identity.Algorithm, KeyID: identity.KeyID(wrong.publicKey),
		PublicKey: base64.RawURLEncoding.EncodeToString(wrong.publicKey),
	}
	if _, err := AuthenticatePublic(context.Background(), path, wrongPublic, Limits{}); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong-key error = %v, want ErrSignature", err)
	}
}
