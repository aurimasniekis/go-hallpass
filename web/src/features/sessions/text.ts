/** Empty or missing server strings render as an explicit placeholder. */
export function orDash(value: string | null | undefined, placeholder = '—'): string {
  return value !== null && value !== undefined && value !== '' ? value : placeholder;
}
