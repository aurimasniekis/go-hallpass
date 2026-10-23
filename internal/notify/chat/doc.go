// Package chat is the seam between the notification core (WP16) and the chat approval providers (Slack WP17,
// Telegram WP18). It holds types, a few pure text helpers and an in-memory replay cache. It performs no network or
// storage I/O.
//
// # Security model (read this before wiring a provider)
//
// Provider packages only AUTHENTICATE THE PLATFORM and IDENTIFY THE PROVIDER USER. They never decide anything:
//
//   - Inbound webhooks are verified (Slack v0 signature + timestamp window + replay cache; Telegram secret token +
//     update_id replay cache + chat/user allowlists) and turned into [Event] values. An [Interaction] says "provider
//     user U in workspace W clicked the button carrying action token T". Nothing more.
//   - Possession of an action token is NEVER authorization (HP-NTF-007, GOAL G-5). The core must look the token up by
//     its HMAC, check that it is unused, unexpired and bound to this provider, take the action and duration from the
//     token record (Interaction.Kind is only a hint and must match the stored action), resolve (Provider, Workspace,
//     UserID) to an operator through provider_links (HP-NTF-011), and call the single transactional decision service
//     (HP-NTF-008), which checks role, approver scope, self-approval, MFA policy (R-10), request state and duration.
//   - Display names (Identity.UserName) are attacker-influenced and must never be used for identity mapping.
//   - A [LinkRequest] carries a user-typed code. The core verifies the code (hashed, single use, 10 min, bound to the
//     issuing operator and provider; PLAN §10.6) and rate limits attempts. The provider packages do not validate it
//     beyond length and character set.
//
// Outbound, providers render [ApprovalMessage] values. All free text (reason, names, descriptions, capabilities,
// decider names) is untrusted: it is cleaned with [CleanText] (controls, bidi overrides, zero-width and other invisible
// characters removed, whitespace collapsed, length bounded) and then escaped or isolated per provider so that it cannot
// produce mentions, links or formatting (HP-NTF-003). Notifications never carry addresses, remote usernames or
// credentials (HP-NTF-004); the message types have no fields for them.
//
// # Errors
//
// Outbound errors wrap [ErrPermanent] (do not retry; the core maps it to outbox.ErrPermanent) or are retryable.
// Rate limiting wraps [ErrRateLimited]; [RetryAfter] extracts the provider-requested delay. Inbound verification
// failures are [*RejectError] values carrying a [RejectReason].
package chat
