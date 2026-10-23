import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { renderWithProviders } from '../../test/utils';
import { PROVENANCE, ProvenanceBadge } from './ProvenanceBadge';

/** "verified" may only ever appear as part of "unverified" (HP-REC-006). */
const CLAIMS_VERIFIED = /(?<!un)verified/i;

describe('command provenance badges (HP-REC-006)', () => {
  it('never claims a command was verified', () => {
    for (const p of Object.values(PROVENANCE)) {
      expect(p.label).not.toMatch(CLAIMS_VERIFIED);
      expect(p.title).not.toMatch(CLAIMS_VERIFIED);
    }
  });

  it('labels gateway-captured and destination-reported commands distinctly', () => {
    renderWithProviders(
      <>
        <ProvenanceBadge provenance="captured" />
        <ProvenanceBadge provenance="destination-audit" />
        <ProvenanceBadge provenance="inferred" />
      </>,
    );
    expect(screen.getByText('Captured')).toBeInTheDocument();
    expect(screen.getByText('Destination-reported, unverified')).toBeInTheDocument();
    expect(screen.getByText('Inferred')).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(CLAIMS_VERIFIED);
  });
});
