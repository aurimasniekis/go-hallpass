<template>
  <figure class="hp-flow">
    <svg viewBox="0 0 900 330" role="img" aria-labelledby="hp-flow-title">
      <title id="hp-flow-title">
        An agent connects to Hallpass with its own SSH key. Hallpass checks policy and human approval, then opens the
        destination session itself with a credential the agent never sees, and records everything.
      </title>
      <defs>
        <marker id="hp-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0,0 L10,5 L0,10 z" class="hp-flow-arrowhead" />
        </marker>
      </defs>

      <!-- agent -->
      <rect x="10" y="40" width="190" height="96" rx="12" class="hp-flow-box" />
      <text x="105" y="80" class="hp-flow-title">AI agent</text>
      <text x="105" y="104" class="hp-flow-sub">holds only its own</text>
      <text x="105" y="122" class="hp-flow-sub">SSH key</text>

      <!-- hallpass -->
      <rect x="320" y="20" width="260" height="136" rx="14" class="hp-flow-box hp-flow-main" />
      <text x="450" y="58" class="hp-flow-title">Hallpass</text>
      <text x="450" y="84" class="hp-flow-sub">policy · approvals · grants</text>
      <text x="450" y="106" class="hp-flow-sub">destination credentials</text>
      <text x="450" y="128" class="hp-flow-sub">encrypted recordings · audit chain</text>

      <!-- destination -->
      <rect x="700" y="40" width="190" height="96" rx="12" class="hp-flow-box" />
      <text x="795" y="80" class="hp-flow-title">Destination</text>
      <text x="795" y="104" class="hp-flow-sub">your server's sshd,</text>
      <text x="795" y="122" class="hp-flow-sub">pinned host key</text>

      <!-- arrows -->
      <line x1="200" y1="88" x2="316" y2="88" class="hp-flow-line" marker-end="url(#hp-arrow)" />
      <text x="258" y="76" class="hp-flow-label">ssh, agent key</text>
      <line x1="580" y1="88" x2="696" y2="88" class="hp-flow-line" marker-end="url(#hp-arrow)" />
      <text x="638" y="70" class="hp-flow-label">ssh, key or</text>
      <text x="638" y="122" class="hp-flow-label">short-lived cert</text>

      <!-- operator -->
      <rect x="320" y="226" width="260" height="84" rx="12" class="hp-flow-box" />
      <text x="450" y="260" class="hp-flow-title">Operator</text>
      <text x="450" y="286" class="hp-flow-sub">web console · Slack · Telegram</text>
      <line x1="450" y1="222" x2="450" y2="160" class="hp-flow-line" marker-end="url(#hp-arrow)" />
      <text x="462" y="196" class="hp-flow-label hp-flow-left">approve, deny, revoke, replay</text>
    </svg>
  </figure>
</template>

<style scoped>
.hp-flow {
  margin: 24px 0;
}
svg {
  width: 100%;
  height: auto;
  font-family: var(--vp-font-family-base);
}
.hp-flow-box {
  fill: var(--vp-c-bg-soft);
  stroke: var(--vp-c-divider);
  stroke-width: 1.5;
}
.hp-flow-main {
  fill: var(--vp-c-brand-soft);
  stroke: var(--vp-c-brand-1);
  stroke-width: 2;
}
.hp-flow-title {
  text-anchor: middle;
  font-size: 19px;
  font-weight: 600;
  fill: var(--vp-c-text-1);
}
.hp-flow-sub {
  text-anchor: middle;
  font-size: 14px;
  fill: var(--vp-c-text-2);
}
.hp-flow-label {
  text-anchor: middle;
  font-size: 13px;
  fill: var(--vp-c-text-2);
}
.hp-flow-left {
  text-anchor: start;
}
.hp-flow-line {
  stroke: var(--vp-c-text-3);
  stroke-width: 2;
}
.hp-flow-arrowhead {
  fill: var(--vp-c-text-3);
}
</style>
