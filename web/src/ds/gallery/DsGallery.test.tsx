import { QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { createTestQueryClient } from '../../test/utils';
import DsGallery from './DsGallery';

// Canvas (ECharts) and xterm rendering are not available in jsdom; they are covered by Playwright snapshots.
vi.mock('../EChart', () => ({ EChart: () => <div role="img" aria-label="chart" /> }));
vi.mock('../TerminalReplay', () => ({ TerminalReplay: () => <div /> }));

describe('/__ds gallery', () => {
  it('renders every component section in both themes', () => {
    const { container } = render(
      <QueryClientProvider client={createTestQueryClient()}>
        <DsGallery />
      </QueryClientProvider>,
    );
    expect(container.querySelectorAll('[data-gallery-theme]')).toHaveLength(2);
    for (const name of [
      'PageHeader',
      'StatusBadge',
      'Countdown',
      'Fingerprint',
      'CopyField',
      'KeyValueGrid',
      'UntrustedText',
      'ConfirmAction',
      'ReauthGate',
      'PermissionGate',
      'ConnectionBanner',
      'DataTable',
      'ChartCard',
      'TerminalReplay (stub)',
      'States',
    ]) {
      expect(screen.getAllByRole('heading', { level: 2, name })).toHaveLength(2);
    }
  });
});
