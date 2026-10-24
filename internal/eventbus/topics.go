package eventbus

// Topics published by HallPass services. Payloads carry IDs only; consumers re-read state from the database.
const (
	TopicAgentChanged     = "agent.changed"
	TopicAgentDisabled    = "agent.disabled"
	TopicAgentKeyRevoked  = "agent.key.revoked"
	TopicInventoryChanged = "inventory.changed"
	TopicTargetDisabled   = "target.disabled"
	TopicCredentialChange = "credential.changed" //nolint:gosec // G101 false positive: topic name
	TopicPolicyChanged    = "policy.changed"
	TopicRequestCreated   = "request.created"
	TopicRequestUpdated   = "request.updated"
	TopicGrantUpdated     = "grant.updated"
	TopicSessionUpdated   = "session.updated"
	TopicActivityStarted  = "activity.started"
	TopicActivityEnded    = "activity.ended"
	TopicLockdown         = "lockdown.changed"
	TopicOperatorChanged  = "operator.changed"
	TopicNotification     = "notification.updated"
	TopicAudit            = "audit.appended"
	TopicSystemStatus     = "system.status"
)
