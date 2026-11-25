package pkg

import (
	"bytes"
	"encoding/json"
	"testing"

	eCrypto "github.com/ente/cli/internal/crypto"
)

func TestEntityEncryptionRoundTrip(t *testing.T) {
	key := eCrypto.NewStreamKey()
	plain := []byte(`{"name":"A","assigned":[{"id":"cluster_x","faces":["123_00100_00200_00300_00400"]}]}`)
	enc, header, err := encryptEntity(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptEntity(enc, header, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %s", got)
	}
	if _, err := decryptEntity(enc, header, eCrypto.NewStreamKey()); err == nil {
		t.Fatal("decryption with wrong key succeeded")
	}
}

func TestSecretBoxSealOpen(t *testing.T) {
	master := eCrypto.NewStreamKey()
	entityKey := eCrypto.NewStreamKey()
	cipher, nonce, err := eCrypto.SecretBoxSeal(entityKey, master)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := eCrypto.SecretBoxOpen(cipher, nonce, master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, entityKey) {
		t.Fatal("secretbox round trip mismatch")
	}
}

func TestPrepareImportedPerson(t *testing.T) {
	in := json.RawMessage(`{"name":"A","email":"a@example.com","userID":42,"manuallyAssigned":[9007199254740993],"futureField":{"x":1}}`)

	out, err := prepareImportedPerson(in, false)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["email"]; ok {
		t.Error("email not stripped")
	}
	if _, ok := m["userID"]; ok {
		t.Error("userID not stripped")
	}
	if string(m["manuallyAssigned"]) != "[9007199254740993]" {
		t.Errorf("large file ID not preserved exactly: %s", m["manuallyAssigned"])
	}
	if _, ok := m["futureField"]; !ok {
		t.Error("unknown field dropped")
	}

	kept, err := prepareImportedPerson(in, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kept, []byte(`"email":"a@example.com"`)) {
		t.Error("email dropped despite keepContactLinks")
	}
}
