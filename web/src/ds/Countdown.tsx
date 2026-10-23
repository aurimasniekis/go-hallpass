import { useNow } from '../lib/useNow';
import { useServerClockOffset } from '../stores/clock';
import { formatRemaining, remainingMs } from './countdownMath';

export interface CountdownProps {
  /** Server-issued deadline (RFC 3339). */
  deadline: string;
  expiredLabel?: string;
  /** Below this many ms the countdown is highlighted (default 60 s). */
  urgentBelowMs?: number;
  /** Overrides the measured offset (gallery/tests). */
  offsetMs?: number;
}

export function Countdown({
  deadline,
  expiredLabel = 'Expired',
  urgentBelowMs = 60_000,
  offsetMs,
}: CountdownProps) {
  const measured = useServerClockOffset();
  const now = useNow(1000);
  const remaining = remainingMs(deadline, now, offsetMs ?? measured);
  const absolute = Number.isFinite(Date.parse(deadline)) ? new Date(deadline).toLocaleString() : deadline;

  if (remaining === null) {
    return <span>Invalid time</span>;
  }
  const text = formatRemaining(remaining);
  const urgent = text !== null && remaining < urgentBelowMs;
  return (
    // role="timer" is implicitly aria-live="off": screen readers are not interrupted every second.
    <time
      role="timer"
      dateTime={deadline}
      title={`Ends ${absolute} (server time)`}
      className={urgent ? 'hp-countdown hp-countdown--urgent' : 'hp-countdown'}
    >
      {text ?? expiredLabel}
    </time>
  );
}
