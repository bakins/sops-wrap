// package sops provides convinience methods for using https://github.com/mozilla/sops as a library
package sops

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"go.mozilla.org/sops"
	"go.mozilla.org/sops/aes"
	"go.mozilla.org/sops/cmd/sops/common"
	"go.mozilla.org/sops/keys"
	sopsjson "go.mozilla.org/sops/stores/json"
	"go.mozilla.org/sops/version"
)

// SopsData is a wrapper around sops data.
// It can be embedded in other structs.
// It has been tested with stldib json and https://github.com/go-yaml/yaml
type SopsData struct {
	data map[string]string
	sops interface{}
	tree *sops.Tree
}

func (d *SopsData) toMap() map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range d.data {
		out[k] = v
	}
	if d.sops != nil {
		out["sops"] = d.sops
	}
	return out
}

// MarshalJSON encodes the data as JSON
func (d SopsData) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.toMap())
}

// MarshalYAML encodes the data as YAML
func (d SopsData) MarshalYAML() (interface{}, error) {
	return d.toMap(), nil
}

// UnmarshalJSON decodes the data from JSON
func (d *SopsData) UnmarshalJSON(data []byte) error {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	return d.fromMap(v)
}

func (d *SopsData) fromMap(v map[string]interface{}) error {
	var s SopsData

	sops, ok := v["sops"]
	if ok {
		delete(v, "sops")
		s.sops = sops
	}

	m := make(map[string]string, len(v))
	for key, val := range v {
		st, ok := val.(string)
		if !ok {
			return fmt.Errorf("invalid type for data key %s", key)
		}
		m[key] = st
	}
	s.data = m

	*d = s
	return nil
}

// UnmarshalYAML decodes the data from YAML
func (d *SopsData) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v map[string]interface{}
	if err := unmarshal(&v); err != nil {
		return err
	}

	return d.fromMap(v)
}

// Data returns the data. It may or may not be encrypted.
// Use IsEncrypted() to check
func (d *SopsData) Data() map[string]string {
	return d.data
}

// IsEncrypted checks if the data is encrypted.
func (d *SopsData) IsEncrypted() bool {
	if d.sops == nil {
		return false
	}

	m, ok := d.sops.(map[string]interface{})
	if !ok {
		return false
	}

	mac, ok := m["mac"].(string)
	if !ok {
		return false
	}

	return mac != ""
}

// NeedsKey checks if a key should be provided to encrypt.
// Generally, a key is only needed the first time data is encrypted.
// if the data comes from a call to Decrypt, then a key is not needed.
// However, one should always check.
func (d *SopsData) NeedsKey() bool {
	if d.tree == nil {
		return true
	}

	return !hasKey(d.tree)
}

// Decrypt the data.  The data must have been encrypted using encrypt.
// You must have access to the key used to encrypt the data.
func (s *SopsData) Decrypt() (*SopsData, error) {
	// sops works on the data directly, so marshal our data
	text, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	store := &sopsjson.Store{}

	tree := s.tree

	if tree == nil {
		t, err := store.LoadEncryptedFile(text)
		if err != nil {
			return nil, err
		}

		tree = &t

	}

	// make a copy of the tree as it is mutated when decrypted
	tmp := *tree
	tree = &tmp

	key, err := tree.Metadata.GetDataKey()
	if err != nil {
		return nil, err
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	decrypted, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, err
	}

	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}

	if originalMac != mac {
		return nil, fmt.Errorf("failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	var sd SopsData

	if err := json.Unmarshal(decrypted, &sd); err != nil {
		return nil, err
	}

	sd.tree = tree

	return &sd, nil
}

// Encrypt the data.  If the data was decrypted before using Decrypt, then
// a key is not needed.  However, always use NeedsKey to check.
// Must have access to the key used to decrypt or the one passed in.
// If the data was decrypted using Decrypt and a key is passed to this function,
// then the key passed in is used to encrypt.
func (s *SopsData) Encrypt(m keys.MasterKey) (*SopsData, error) {

	tree := s.tree

	store := &sopsjson.Store{}

	if tree == nil {
		// sops works on the data directly, so marshal our data
		text, err := json.Marshal(s)
		if err != nil {
			return nil, err
		}

		branches, err := store.LoadPlainFile(text)
		if err != nil {
			return nil, err
		}

		t := sops.Tree{
			Metadata: sops.Metadata{
				KeyGroups: []sops.KeyGroup{
					{
						m,
					},
				},
				Version: version.Version,
			},
			Branches: branches,
		}
		tree = &t

	}

	// make a copy of the tree as it is mutated when encrypted
	tmp := *tree
	tree = &tmp

	if m != nil && !reflect.ValueOf(m).IsNil() {
		tree.Metadata.KeyGroups = []sops.KeyGroup{{m}}
	}

	if !hasKey(tree) {
		return nil, errors.New("key is needed and one was not provided")
	}

	key, errors := tree.GenerateDataKey()
	if len(errors) > 0 {
		return nil, fmt.Errorf("%v", errors)
	}

	err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: key,
		Tree:    tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		return nil, err
	}

	encTree, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, err
	}

	var sd SopsData

	if err := json.Unmarshal(encTree, &sd); err != nil {
		return nil, err
	}

	sd.tree = tree
	return &sd, nil
}

func hasKey(tree *sops.Tree) bool {
	for _, group := range tree.Metadata.KeyGroups {
		for _, k := range group {
			if k != nil && !reflect.ValueOf(k).IsNil() {
				return true
			}
		}
	}
	return false
}
