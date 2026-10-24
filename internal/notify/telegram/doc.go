// Package telegram is the Telegram Bot API approval provider (WP18, HP-NTF-006).
//
// # It identifies, it never decides
//
// The inbound side authenticates Telegram and reports WHO pressed WHICH button. It never approves, denies or links:
// [Handler] turns verified updates into chat.Event values for the core's chat.Sink. Possession of an action token is
// not authorization; the core resolves (bot ID, from.id) through provider_links to an operator and runs the single
// transactional decision service (PLAN §10.1, HP-NTF-007, HP-NTF-008). See internal/notify/chat.
//
// # Inbound verification (PLAN §10.5)
//
// [Webhook] checks, in this order: X-Telegram-Bot-Api-Secret-Token compared in constant time (hashes of equal length)
// → body size (64 KiB) → JSON → update_id replay cache (fail closed) → for callback queries, the chat ID and the
// user ID must both pass the [Allowlist] (the core allows route-destination chats and maps users through links; [StaticAllowlist] is
// for configuration and tests) → callback_data must be "hp1:<a|d>:<action-token-id>". Updates from other chats or
// users are ignored (HTTP 200, so Telegram does not retry) and reported to Sink.Rejected for audit.
//
// Linking exception: "/link <code>" is accepted from users who are not yet allowlisted, because linking is how they
// become allowed. It is forwarded with PrivateChat=true only for a private chat with the bot (chat.id == from.id).
// A /link seen in a group is forwarded with PrivateChat=false: the core MUST refuse it and burn the code, because
// other group members have seen it. All other messages are ignored.
//
// # Outbound (HP-NTF-002..004)
//
// Messages are sent without parse_mode (plain text), with explicit message entities: untrusted text (names,
// descriptions, capabilities, reason, decider) is cleaned with chat.CleanText and placed inside "code"/"pre"
// entities, which Telegram renders literally (no mentions, commands, links or formatting); in addition '@' and '/'
// inside untrusted spans are followed by U+2060 WORD JOINER as defense in depth against auto-detected mentions,
// bot commands and URLs. Link previews are disabled. callback_data carries only the action-token ID and kind and is
// checked to be ≤ 64 bytes at render time. The rendered text is checked against the 4096 UTF-16 unit limit and
// shortened by tiers if needed.
//
// The bot token appears only in the request URL path. Errors never include it: transport errors are unwrapped from
// *url.Error, any remaining occurrence is redacted, and redirects are not followed. HTTP 429 returns a
// *chat.RateLimitError with parameters.retry_after.
//
// Real-Telegram behavior (entity rendering, absence of mention notifications) still needs externally verified
// evidence (PLAN WP18).
package telegram
