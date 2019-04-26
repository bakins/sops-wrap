package sops

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	kms "go.mozilla.org/sops/gcpkms"
)

func TestRoundTrip(t *testing.T) {
	key := os.Getenv("KMS_KEY")
	require.NotEmpty(t, key, "must set KMS_KEY to a GCP KMS resource ID")

	g := kms.NewMasterKeyFromResourceID(key)
	require.NotNil(t, g)

	type myData struct {
		Foo       string   `json:"foo" yaml:"foo"`
		Encrypted SopsData `json:"encrypted" yaml:"encrypted"`
	}

	var testData = `{"foo":"bar", "encrypted": { "key": "value" }}`

	var md myData
	err := json.Unmarshal([]byte(testData), &md)
	require.NoError(t, err)

	require.False(t, md.Encrypted.IsEncrypted())
	require.True(t, md.Encrypted.NeedsKey())

	encrypted, err := md.Encrypted.Encrypt(g)
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	require.True(t, encrypted.IsEncrypted())
	require.False(t, encrypted.NeedsKey())

	decrypted, err := encrypted.Decrypt()
	require.NoError(t, err)
	require.NotNil(t, decrypted)

	require.False(t, decrypted.IsEncrypted())
	require.False(t, decrypted.NeedsKey())

	data := decrypted.Data()
	require.NotEmpty(t, data)
	require.Equal(t, map[string]string{"key": "value"}, data)

	encrypted, err = decrypted.Encrypt(nil)
	require.NoError(t, err)
	require.NotNil(t, encrypted)

	require.True(t, encrypted.IsEncrypted())
	require.False(t, encrypted.NeedsKey())
}
