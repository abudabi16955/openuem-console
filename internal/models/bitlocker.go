package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/bitlockerkey"
	"github.com/open-uem/openuem-console/internal/crypto"
)

// BitLockerKeyWithAgent associates a BitLocker recovery key with its owner Agent.
type BitLockerKeyWithAgent struct {
	Key   *ent.BitlockerKey
	Agent *ent.Agent
}

// GetBitLockerKeysForAgent retrieves all BitLocker keys for a given agent sorted by created_at DESC.
func (m *Model) GetBitLockerKeysForAgent(agentID string) ([]*ent.BitlockerKey, error) {
	if m == nil || m.Client == nil {
		return nil, errors.New("database client is nil")
	}

	return m.Client.BitlockerKey.Query().
		Where(bitlockerkey.AgentIDEQ(agentID)).
		Order(ent.Desc(bitlockerkey.FieldCreatedAt)).
		All(context.Background())
}

// GetActiveBitLockerKeysForAgent retrieves only active BitLocker keys for a given agent sorted by created_at DESC.
func (m *Model) GetActiveBitLockerKeysForAgent(agentID string) ([]*ent.BitlockerKey, error) {
	if m == nil || m.Client == nil {
		return nil, errors.New("database client is nil")
	}

	return m.Client.BitlockerKey.Query().
		Where(
			bitlockerkey.AgentIDEQ(agentID),
			bitlockerkey.IsActiveEQ(true),
		).
		Order(ent.Desc(bitlockerkey.FieldCreatedAt)).
		All(context.Background())
}

// SearchBitLockerKeys searches for BitLocker keys whose key_id contains or begins with the given query.
func (m *Model) SearchBitLockerKeys(keyQuery string) ([]*ent.BitlockerKey, error) {
	if m == nil || m.Client == nil {
		return nil, errors.New("database client is nil")
	}

	trimmed := strings.TrimSpace(keyQuery)
	if trimmed == "" {
		return nil, nil
	}

	return m.Client.BitlockerKey.Query().
		Where(bitlockerkey.KeyIDContainsFold(trimmed)).
		Order(ent.Desc(bitlockerkey.FieldCreatedAt)).
		All(context.Background())
}

// SearchBitLockerKeysWithAgent finds BitLocker keys matching the keyQuery and returns them alongside their Agent details.
func (m *Model) SearchBitLockerKeysWithAgent(keyQuery string) ([]*BitLockerKeyWithAgent, error) {
	keys, err := m.SearchBitLockerKeys(keyQuery)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, nil
	}

	// Collect unique agent IDs
	agentIDMap := make(map[string]struct{})
	for _, k := range keys {
		if k.AgentID != "" {
			agentIDMap[k.AgentID] = struct{}{}
		}
	}

	agentIDs := make([]string, 0, len(agentIDMap))
	for id := range agentIDMap {
		agentIDs = append(agentIDs, id)
	}

	agents, err := m.Client.Agent.Query().
		Where(agent.IDIn(agentIDs...)).
		WithComputer().
		WithOperatingsystem().
		WithTags().
		All(context.Background())
	if err != nil {
		return nil, fmt.Errorf("could not query agents for bitlocker keys: %w", err)
	}

	agentsByID := make(map[string]*ent.Agent, len(agents))
	for _, a := range agents {
		agentsByID[a.ID] = a
	}

	results := make([]*BitLockerKeyWithAgent, 0, len(keys))
	for _, k := range keys {
		results = append(results, &BitLockerKeyWithAgent{
			Key:   k,
			Agent: agentsByID[k.AgentID],
		})
	}

	return results, nil
}

// RevealBitLockerKey atomically logs the read action to AuditLog within a database transaction
// and decrypts the recovery password using the vault key.
// If the reason has fewer than 5 characters, a validation error is returned.
// If the audit log fails to save, the transaction is rolled back and an error is returned.
func (m *Model) RevealBitLockerKey(agentID, keyID, reason, userID, ipAddress string) (string, error) {
	if m == nil || m.Client == nil {
		return "", errors.New("database client is nil")
	}

	trimmedReason := strings.TrimSpace(reason)
	if len(trimmedReason) < 5 {
		return "", fmt.Errorf("reason must be at least 5 characters long")
	}

	if agentID == "" {
		return "", errors.New("agent ID cannot be empty")
	}
	if keyID == "" {
		return "", errors.New("key ID cannot be empty")
	}

	// Determine vault key to use
	vaultKey := m.VaultKey
	if len(vaultKey) != crypto.KeySize {
		var err error
		vaultKey, err = crypto.GetVaultKey()
		if err != nil {
			return "", fmt.Errorf("vault key not available: %w", err)
		}
	}

	ctx := context.Background()

	// Begin atomic transaction
	tx, err := m.Client.Tx(ctx)
	if err != nil {
		return "", fmt.Errorf("could not start database transaction: %w", err)
	}

	// 1. Fetch the BitLocker key record
	key, err := tx.BitlockerKey.Query().
		Where(
			bitlockerkey.AgentIDEQ(agentID),
			bitlockerkey.KeyIDEQ(keyID),
		).
		First(ctx)
	if err != nil {
		_ = tx.Rollback()
		if ent.IsNotFound(err) {
			return "", fmt.Errorf("bitlocker key not found for agent %s and key ID %s", agentID, keyID)
		}
		return "", fmt.Errorf("could not query bitlocker key: %w", err)
	}

	// 2. Insert audit log record
	_, err = tx.AuditLog.Create().
		SetUserID(userID).
		SetAgentID(agentID).
		SetAction("BITLOCKER_RECOVERY_KEY_READ").
		SetReason(trimmedReason).
		SetIPAddress(ipAddress).
		SetCreatedAt(time.Now()).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return "", fmt.Errorf("failed to save audit log: %w", err)
	}

	// 3. Commit transaction
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	// 4. Decrypt recovery password using AES-256-GCM vault key
	decryptedPassword, err := crypto.DecryptRecoveryPassword(key.EncryptedPassword, vaultKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt recovery password: %w", err)
	}

	return decryptedPassword, nil
}
