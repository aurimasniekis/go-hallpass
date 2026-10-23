/** Duration choices offered when approving (seconds; 0 means "the requested duration"). */
export const DURATION_PRESETS: readonly number[] = [15 * 60, 3_600, 4 * 3_600, 8 * 3_600];

export type DurationChoice = { kind: 'requested' } | { kind: 'preset'; seconds: number } | { kind: 'custom' };

/** `approve` body: `duration` 0 asks the server to use the requested duration (it applies policy bounds). */
export function approveBody(
  choice: DurationChoice,
  customSeconds: number | null,
  comment: string,
): { duration: number; comment?: string } | null {
  let duration: number;
  if (choice.kind === 'requested') {
    duration = 0;
  } else if (choice.kind === 'preset') {
    duration = choice.seconds;
  } else {
    if (customSeconds === null || !Number.isFinite(customSeconds) || customSeconds < 60) {
      return null;
    }
    duration = Math.round(customSeconds);
  }
  const trimmed = comment.trim();
  return trimmed === '' ? { duration } : { duration, comment: trimmed };
}

export function choiceKey(choice: DurationChoice): string {
  return choice.kind === 'preset' ? `preset:${String(choice.seconds)}` : choice.kind;
}

export function parseChoiceKey(key: string): DurationChoice {
  if (key.startsWith('preset:')) {
    return { kind: 'preset', seconds: Number(key.slice('preset:'.length)) };
  }
  return key === 'custom' ? { kind: 'custom' } : { kind: 'requested' };
}
