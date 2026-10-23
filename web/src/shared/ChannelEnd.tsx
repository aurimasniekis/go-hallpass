import {
  describeChannelEnd,
  GATEWAY_EXIT_CODES,
  GATEWAY_EXIT_LEGEND,
  type ChannelEndInput,
} from './channelClose';

/**
 * Why a channel ended: readable reason, the gateway's classified detail and its exit code. Renders `—`
 * for live channels. Every value is plain text (details are gateway-classified and never hold addresses).
 */
export function ChannelEndCell({ channel }: { channel: ChannelEndInput }) {
  const end = describeChannelEnd(channel);
  if (!end.reason && !end.detail && !end.gatewayExit) {
    return <>—</>;
  }
  return (
    <div className="hp-chan-end">
      <span
        className={
          end.tone === 'error'
            ? 'hp-chan-end__reason hp-chan-end__reason--error'
            : end.tone === 'warning'
              ? 'hp-chan-end__reason hp-chan-end__reason--warning'
              : 'hp-chan-end__reason'
        }
      >
        {end.reason ?? 'Ended'}
      </span>
      {end.detail ? <span className="hp-chan-end__detail">{end.detail}</span> : null}
      {end.gatewayExit ? <span className="hp-chan-end__detail">Gateway exit {end.gatewayExit}</span> : null}
    </div>
  );
}

/** One-line legend for the gateway exit codes shown in channel tables. */
export function GatewayExitLegend() {
  return (
    <p className="hp-legend">
      Gateway exit codes (the gateway, not the destination, ended the channel):{' '}
      {GATEWAY_EXIT_LEGEND.map((code, i) => (
        <span key={code}>
          {i > 0 ? ' · ' : null}
          <strong>{code}</strong> {GATEWAY_EXIT_CODES[code]}
        </span>
      ))}
      .
    </p>
  );
}
