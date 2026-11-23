package locales

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var expectedBitLockerKeys = []string{
	"bitlocker",
	"bitlocker_encrypted",
	"bitlocker_unencrypted",
	"bitlocker_unknown",
	"bitlocker_unsupported",
	"bitlocker_title",
	"bitlocker_description",
	"bitlocker_key_id",
	"bitlocker_recovery_password",
	"bitlocker_active",
	"bitlocker_rotated",
	"bitlocker_reveal",
	"bitlocker_copy",
	"bitlocker_copied",
	"bitlocker_force_escrow",
	"bitlocker_force_escrow_requested",
	"bitlocker_force_escrow_failed",
	"bitlocker_history",
	"bitlocker_no_keys",
	"bitlocker_modal_title",
	"bitlocker_modal_desc",
	"bitlocker_reason_label",
	"bitlocker_reason_placeholder",
	"bitlocker_escrowed_at",
}

func TestLocales_BitLockerKeysComplete(t *testing.T) {
	locales := []string{"en", "ca", "de", "es", "fr", "no", "pt"}

	for _, loc := range locales {
		t.Run(loc, func(t *testing.T) {
			path := filepath.Join(".", loc+".yaml")
			data, err := os.ReadFile(path)
			require.NoError(t, err, "failed to read locale file %s", path)

			var raw map[string]interface{}
			err = yaml.Unmarshal(data, &raw)
			require.NoError(t, err, "failed to parse YAML for %s", path)

			// The root key is the locale name
			var rootMap map[string]interface{}
			for _, v := range raw {
				if m, ok := v.(map[string]interface{}); ok {
					rootMap = m
					break
				}
			}
			require.NotNil(t, rootMap, "root map not found in %s", path)

			inv, ok := rootMap["inventory"].(map[string]interface{})
			require.True(t, ok, "inventory section missing in %s", path)

			disks, ok := inv["logical_disk"].(map[string]interface{})
			require.True(t, ok, "logical_disk section missing in %s", path)

			for _, expectedKey := range expectedBitLockerKeys {
				val, exists := disks[expectedKey]
				assert.True(t, exists, "missing key %s in %s.yaml", expectedKey, loc)
				if exists {
					s, isStr := val.(string)
					assert.True(t, isStr, "key %s in %s.yaml is not string", expectedKey, loc)
					assert.NotEmpty(t, s, "key %s in %s.yaml has empty translation", expectedKey, loc)
				}
			}
		})
	}
}
