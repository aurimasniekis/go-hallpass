import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiError } from '../api/errors';
import { renderWithProviders } from '../test/utils';
import { ConfirmAction } from './ConfirmAction';

describe('<ConfirmAction>', () => {
  it('requires the exact typed phrase before confirming', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn(() => Promise.resolve('ok'));
    renderWithProviders(
      <ConfirmAction
        label="Lock down"
        title="Enter lockdown"
        typedConfirmation="LOCKDOWN"
        onConfirm={onConfirm}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Lock down' }));
    const confirm = await screen.findByRole('button', { name: 'Confirm' });
    expect(confirm).toBeDisabled();
    const input = screen.getByLabelText(/to confirm/);
    await user.type(input, 'lockdown');
    expect(confirm).toBeDisabled();
    await user.clear(input);
    await user.type(input, 'LOCKDOWN');
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => {
      expect(onConfirm).toHaveBeenCalledTimes(1);
    });
  });

  it('reports success only after the server resolves (no optimistic success)', async () => {
    const user = userEvent.setup();
    let resolve: (v: string) => void = () => undefined;
    const onConfirm = vi.fn(
      () =>
        new Promise<string>((r) => {
          resolve = r;
        }),
    );
    const onSuccess = vi.fn();
    renderWithProviders(
      <ConfirmAction label="Revoke" title="Revoke grant" onConfirm={onConfirm} onSuccess={onSuccess} />,
    );
    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await user.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onSuccess).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    resolve('revoked');
    await waitFor(() => {
      expect(onSuccess).toHaveBeenCalledWith('revoked');
    });
  });

  it('keeps the dialog open and shows the server error on failure', async () => {
    const user = userEvent.setup();
    const onSuccess = vi.fn();
    const onConfirm = () =>
      Promise.reject(new ApiError({ status: 409, code: 'conflict', detail: 'Grant already ended' }));
    renderWithProviders(
      <ConfirmAction label="Revoke" title="Revoke grant" onConfirm={onConfirm} onSuccess={onSuccess} />,
    );
    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await user.click(await screen.findByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('Grant already ended')).toBeInTheDocument();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});
