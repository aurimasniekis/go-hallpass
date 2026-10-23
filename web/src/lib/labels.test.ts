import { describe, expect, it } from 'vitest';

import { labelsToTags, tagsToLabels } from './labels';

describe('labels', () => {
  it('round-trips label maps through sorted key=value tags', () => {
    expect(labelsToTags({ team: 'ops', env: 'prod' })).toEqual(['env=prod', 'team=ops']);
    expect(tagsToLabels(['env=prod', 'team = ops'])).toEqual({
      labels: { env: 'prod', team: 'ops' },
      invalid: [],
    });
    expect(labelsToTags(null)).toEqual([]);
  });

  it('reports malformed tags and keeps values containing "="', () => {
    expect(tagsToLabels(['novalue', '=x', 'a=b=c'])).toEqual({
      labels: { a: 'b=c' },
      invalid: ['novalue', '=x'],
    });
  });
});
