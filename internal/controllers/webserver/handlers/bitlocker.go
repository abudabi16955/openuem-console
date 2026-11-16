package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-console/internal/views/computers_views"
)

// RevealBitLockerKey handles requests to reveal a BitLocker recovery password.
// It requires a non-empty key_id and a reason of at least 5 characters.
// The reveal action is logged to AuditLog atomically before returning the plaintext password.
func (h *Handler) RevealBitLockerKey(c echo.Context) error {
	agentId := c.Param("uuid")
	if agentId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing uuid parameter")
	}

	keyId := c.FormValue("key_id")
	if keyId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing key_id parameter")
	}

	reason := c.FormValue("reason")
	if len(strings.TrimSpace(reason)) < 5 {
		return echo.NewHTTPError(http.StatusBadRequest, "reason must be at least 5 characters long")
	}

	userId := ""
	if h.SessionManager != nil && h.SessionManager.Manager != nil {
		userId = h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	}
	if userId == "" {
		userId = "unknown"
	}

	ipAddress := c.RealIP()
	if ipAddress == "" {
		ipAddress = c.Request().RemoteAddr
	}

	password, err := h.Model.RevealBitLockerKey(agentId, keyId, reason, userId, ipAddress)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to reveal recovery key: %v", err))
	}

	return RenderView(c, computers_views.BitLockerKeyRevealed(keyId, password))
}

// ForceBitLockerEscrow sends a force escrow request via NATS to the specified agent.
func (h *Handler) ForceBitLockerEscrow(c echo.Context) error {
	agentId := c.Param("uuid")
	if agentId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing uuid parameter")
	}

	if h.NATSConnection == nil || !h.NATSConnection.IsConnected() {
		return echo.NewHTTPError(http.StatusInternalServerError, "NATS connection is not available")
	}

	userId := ""
	if h.SessionManager != nil && h.SessionManager.Manager != nil {
		userId = h.SessionManager.Manager.GetString(c.Request().Context(), "uid")
	}

	driveLetter := c.FormValue("drive_letter")

	req := openuem_nats.BitLockerForceEscrowRequest{
		AgentID:     agentId,
		DriveLetter: driveLetter,
		RequestedBy: userId,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to serialize force escrow request: %v", err))
	}

	subject := openuem_nats.BitLockerForceEscrowSubject(agentId)
	if err := h.NATSConnection.Publish(subject, data); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to publish force escrow request: %v", err))
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "force escrow requested",
	})
}
