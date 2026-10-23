// Package slack is the Slack approval provider (WP17, HP-NTF-005).
//
// # It identifies, it never decides
//
// The inbound side authenticates Slack and reports WHO clicked WHAT. It never approves, denies or links anything:
// [Handler] turns verified requests into chat.Event values and hands them to the core's chat.Sink. Possession of a
// button's action token is not authorization. The core must resolve (team ID, user ID) through provider_links to an
// operator and run the single transactional decision service (PLAN §10.1, HP-NTF-007, HP-NTF-008). See package
// internal/notify/chat for the full contract.
//
// # Inbound verification (PLAN §10.4)
//
// [Verifier] checks, in this order: body size (64 KiB) → X-Slack-Request-Timestamp within ±5 minutes of the injected
// clock → v0 signature HMAC-SHA256(signing_secret, "v0:" + ts + ":" + body) compared in constant time → replay cache
// insert of sha256(decoded signature) for 10 minutes (fail closed if the cache errors). Only then is the body parsed.
// [ParseBody] accepts block_actions interactions with exactly one Hallpass button and the /hallpass slash command
// (link <code>, status <request-id>, help), and rejects payloads from any team other than the configured one.
//
// # Outbound (HP-NTF-002..004)
//
// [Client] posts Block Kit messages with chat.postMessage and edits them with chat.update. Untrusted text (reason,
// names, descriptions, capabilities, decider) is cleaned with chat.CleanText and placed ONLY in plain_text objects
// (emoji off) after escaping &, < and >. The renderer never emits mrkdwn objects, so formatting, <!channel>/<!here>,
// <@U…>, <#C…> and <url|label> sequences cannot be produced; messages set parse=none, link_names=false and disable
// unfurling. The notification fallback text contains only the request ID. Button payloads carry only
// "hp1:<a|d>:<action-token-id>".
//
// The bot token is sent only in the Authorization header and is never logged or included in errors; redirects are
// not followed. Slack "ok":false errors are classified as permanent (chat.ErrPermanent) or retryable; HTTP 429 and
// "ratelimited" return a *chat.RateLimitError carrying Retry-After.
//
// Real-workspace behavior (rendering of escaped plain_text, absence of mention notifications) still needs externally
// verified evidence (PLAN WP17).
package slack
