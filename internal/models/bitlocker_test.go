package models

import (
	"context"
	"crypto/rand"
	"strconv"
	"testing"
	"time"

	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/auditlog"
	"github.com/open-uem/ent/enttest"
	"github.com/open-uem/openuem-console/internal/crypto"
	"github.com/open-uem/openuem-console/internal/views/filters"
	"github.com/open-uem/openuem-console/internal/views/partials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestModelWithVaultKey(t *testing.T) (*Model, []byte) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&_fk=1")
	t.Cleanup(func() {
		_ = client.Close()
	})

	key := make([]byte, crypto.KeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)

	model := &Model{
		Client:   client,
		VaultKey: key,
	}
	return model, key
}

func TestGetBitLockerKeysForAgent(t *testing.T) {
	model, key := setupTestModelWithVaultKey(t)
	ctx := context.Background()

	agentID := "agent-uuid-1"
	enc1, _ := crypto.EncryptRecoveryPassword("111111-111111", key)
	enc2, _ := crypto.EncryptRecoveryPassword("222222-222222", key)
	enc3, _ := crypto.EncryptRecoveryPassword("333333-333333", key)

	now := time.Now()
	// Old inactive key
	_, err := model.Client.BitlockerKey.Create().
		SetAgentID(agentID).
		SetDriveLetter("C:").
		SetKeyID("{KEY-1}").
		SetEncryptedPassword(enc1).
		SetIsActive(false).
		SetCreatedAt(now.Add(-2 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	// Newer inactive key
	_, err = model.Client.BitlockerKey.Create().
		SetAgentID(agentID).
		SetDriveLetter("C:").
		SetKeyID("{KEY-2}").
		SetEncryptedPassword(enc2).
		SetIsActive(false).
		SetCreatedAt(now.Add(-1 * time.Hour)).
		Save(ctx)
	require.NoError(t, err)

	// Latest active key
	_, err = model.Client.BitlockerKey.Create().
		SetAgentID(agentID).
		SetDriveLetter("C:").
		SetKeyID("{KEY-3}").
		SetEncryptedPassword(enc3).
		SetIsActive(true).
		SetCreatedAt(now).
		Save(ctx)
	require.NoError(t, err)

	// Other agent key
	_, err = model.Client.BitlockerKey.Create().
		SetAgentID("agent-other").
		SetDriveLetter("C:").
		SetKeyID("{KEY-OTHER}").
		SetEncryptedPassword(enc1).
		SetIsActive(true).
		SetCreatedAt(now).
		Save(ctx)
	require.NoError(t, err)

	// 1. Get all keys for agentID (sorted created_at DESC)
	allKeys, err := model.GetBitLockerKeysForAgent(agentID)
	require.NoError(t, err)
	assert.Len(t, allKeys, 3)
	assert.Equal(t, "{KEY-3}", allKeys[0].KeyID)
	assert.Equal(t, "{KEY-2}", allKeys[1].KeyID)
	assert.Equal(t, "{KEY-1}", allKeys[2].KeyID)

	// 2. Get only active keys
	activeKeys, err := model.GetActiveBitLockerKeysForAgent(agentID)
	require.NoError(t, err)
	assert.Len(t, activeKeys, 1)
	assert.Equal(t, "{KEY-3}", activeKeys[0].KeyID)
}

func TestSearchBitLockerKeysAndWithAgent(t *testing.T) {
	model, key := setupTestModelWithVaultKey(t)
	ctx := context.Background()

	enc, _ := crypto.EncryptRecoveryPassword("123456-654321", key)

	// Create Agent
	agentRecord, err := model.Client.Agent.Create().
		SetID("agent-search-1").
		SetHostname("DESKTOP-WIN11").
		SetNickname("Executive Laptop").
		SetOs("windows").
		Save(ctx)
	require.NoError(t, err)

	// Create BitLocker Key
	_, err = model.Client.BitlockerKey.Create().
		SetAgentID(agentRecord.ID).
		SetDriveLetter("C:").
		SetKeyID("{ABCD-1234-EFGH}").
		SetEncryptedPassword(enc).
		SetIsActive(true).
		Save(ctx)
	require.NoError(t, err)

	// Search matching key
	results, err := model.SearchBitLockerKeys("abcd")
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "{ABCD-1234-EFGH}", results[0].KeyID)

	// Search matching with Agent
	withAgent, err := model.SearchBitLockerKeysWithAgent("1234")
	require.NoError(t, err)
	assert.Len(t, withAgent, 1)
	assert.Equal(t, "{ABCD-1234-EFGH}", withAgent[0].Key.KeyID)
	assert.NotNil(t, withAgent[0].Agent)
	assert.Equal(t, "Executive Laptop", withAgent[0].Agent.Nickname)

	// Search non-existent
	empty, err := model.SearchBitLockerKeys("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestRevealBitLockerKey_Success(t *testing.T) {
	model, key := setupTestModelWithVaultKey(t)
	ctx := context.Background()

	originalPassword := "481234-567890-112233-445566-778899-001122-334455-667788"
	encPassword, err := crypto.EncryptRecoveryPassword(originalPassword, key)
	require.NoError(t, err)

	agentID := "agent-reveal-test"
	keyID := "{REVEAL-KEY-001}"

	_, err = model.Client.BitlockerKey.Create().
		SetAgentID(agentID).
		SetDriveLetter("C:").
		SetKeyID(keyID).
		SetEncryptedPassword(encPassword).
		SetIsActive(true).
		Save(ctx)
	require.NoError(t, err)

	reason := "Emergency system restore after blue screen"
	userID := "admin-user-42"
	ipAddress := "192.168.1.100"

	revealed, err := model.RevealBitLockerKey(agentID, keyID, reason, userID, ipAddress)
	require.NoError(t, err)
	assert.Equal(t, originalPassword, revealed)

	// Verify AuditLog was saved atomically
	logs, err := model.Client.AuditLog.Query().
		Where(
			auditlog.AgentIDEQ(agentID),
			auditlog.ActionEQ("BITLOCKER_RECOVERY_KEY_READ"),
		).
		All(ctx)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	assert.Equal(t, userID, logs[0].UserID)
	assert.Equal(t, agentID, logs[0].AgentID)
	assert.Equal(t, "BITLOCKER_RECOVERY_KEY_READ", logs[0].Action)
	assert.Equal(t, reason, logs[0].Reason)
	assert.Equal(t, ipAddress, logs[0].IPAddress)
}

func TestRevealBitLockerKey_ReasonValidation(t *testing.T) {
	model, _ := setupTestModelWithVaultKey(t)

	invalidReasons := []string{
		"",
		"   ",
		"123",
		"help", // 4 chars
		" a  ", // trimmed to 1 char
	}

	for _, r := range invalidReasons {
		_, err := model.RevealBitLockerKey("agent-1", "{KEY-1}", r, "user1", "127.0.0.1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 5 characters")
	}

	// Verify no audit logs were created
	count, err := model.Client.AuditLog.Query().Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRevealBitLockerKey_KeyNotFound(t *testing.T) {
	model, _ := setupTestModelWithVaultKey(t)

	_, err := model.RevealBitLockerKey("agent-nonexistent", "{KEY-NOT-FOUND}", "Valid reason for unlock", "user1", "127.0.0.1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Verify no audit logs
	count, err := model.Client.AuditLog.Query().Count(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestSearchComputerByBitLockerKey(t *testing.T) {
	model, key := setupTestModelWithVaultKey(t)
	ctx := context.Background()

	tenant, err := model.CreateDefaultTenant()
	require.NoError(t, err)

	site, err := model.CreateDefaultSite(tenant)
	require.NoError(t, err)

	commonInfo := &partials.CommonInfo{
		TenantID: strconv.Itoa(tenant.ID),
		SiteID:   "-1",
	}

	// Create agent
	agentRecord, err := model.Client.Agent.Create().
		SetID("agent-bitlocker-search").
		SetHostname("WIN-SECRET").
		SetNickname("Secret Laptop").
		SetOs("windows").
		SetAgentStatus(agent.AgentStatusEnabled).
		AddSiteIDs(site.ID).
		Save(ctx)
	require.NoError(t, err)

	enc, err := crypto.EncryptRecoveryPassword("123456-789012", key)
	require.NoError(t, err)

	_, err = model.Client.BitlockerKey.Create().
		SetAgentID(agentRecord.ID).
		SetDriveLetter("C:").
		SetKeyID("{SPECIAL-KEY-9999}").
		SetEncryptedPassword(enc).
		SetIsActive(true).
		Save(ctx)
	require.NoError(t, err)

	p := partials.NewPaginationAndSort(10)

	// Search by full or partial key ID
	f := filters.AgentFilter{Search: "SPECIAL-KEY"}
	count, err := model.CountAllComputers(f, commonInfo)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	comps, err := model.GetComputersByPage(p, f, commonInfo)
	require.NoError(t, err)
	require.Len(t, comps, 1)
	assert.Equal(t, "Secret Laptop", comps[0].Nickname)
}
