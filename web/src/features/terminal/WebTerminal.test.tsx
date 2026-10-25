import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe, problemResponse } from '../../test/fixtures';
import { mockApi } from '../policy/mockApi';
import { renderInRouter } from '../requests/testHelpers';
import { streamURL, WebTerminal } from './WebTerminal';

// xterm needs a real canvas; a fake records what reaches the screen and lets the test type.
const written: (string | Uint8Array)[] = [];
let typed: ((data: string) => void) | undefined;
vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    element: HTMLElement | undefined;
    parser = { registerOscHandler: () => ({ dispose: () => undefined }) };
    open(el: HTMLElement) {
      this.element = el;
    }
    write(d: string | Uint8Array) {
      written.push(d);
    }
    onData(cb: (data: string) => void) {
      typed = cb;
      return { dispose: () => undefined };
    }
    focus() {
      return undefined;
    }
    dispose() {
      return undefined;
    }
  },
}));
vi.mock('@xterm/xterm/css/xterm.css', () => ({}));

class FakeSocket {
  static last: FakeSocket | undefined;
  static OPEN = 1;
  readyState = 1;
  binaryType = '';
  sent: string[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: ArrayBuffer | string }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) {
    FakeSocket.last = this;
  }
  send(d: string) {
    this.sent.push(d);
  }
  close() {
    this.closed = true;
    this.onclose?.();
  }
}

const opened = {
  grant_id: 'grt_1',
  session_id: 'ses_1',
  server_id: 'srv_1',
  role_id: 'rol_1',
  remote_user: 'ops',
  expires_at: '2099-01-01T00:00:00Z',
  ticket: 'tkt+1',
  stream_path: '/api/v1/terminals/grt_1/stream',
};

describe('<WebTerminal>', () => {
  beforeEach(() => {
    written.length = 0;
    typed = undefined;
    FakeSocket.last = undefined;
    vi.stubGlobal('WebSocket', FakeSocket);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('opens the grant, connects with the ticket, forwards typing and output, and shows the exit', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe(),
      'POST /api/v1/terminals': () => jsonResponse(201, opened),
    });
    const onClose = vi.fn();
    renderInRouter(<WebTerminal serverId="srv_1" roleId="rol_1" title="ops (ops)" onClose={onClose} />);
    await waitFor(() => {
      expect(FakeSocket.last).toBeDefined();
    });
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ server_id: 'srv_1', role_id: 'rol_1' });
    const sock = FakeSocket.last;
    if (!sock) {
      throw new Error('no socket');
    }
    expect(sock.url).toBe(`ws://${window.location.host}/api/v1/terminals/grt_1/stream?ticket=tkt%2B1`);
    act(() => {
      sock.onopen?.();
    });
    expect(JSON.parse(sock.sent[0] ?? '{}')).toEqual({ type: 'resize', cols: 120, rows: 32 });
    act(() => {
      typed?.('ls\r');
    });
    expect(JSON.parse(sock.sent[1] ?? '{}')).toEqual({ type: 'input', data: 'ls\r' });
    act(() => {
      sock.onmessage?.({ data: new TextEncoder().encode('file.txt\r\n').buffer });
    });
    expect(
      written.some((w) => w instanceof Uint8Array && new TextDecoder().decode(w) === 'file.txt\r\n'),
    ).toBe(true);
    expect(screen.getByText('Recorded')).toBeInTheDocument();
    act(() => {
      sock.onmessage?.({ data: JSON.stringify({ type: 'exit', status: 0 }) });
    });
    expect(await screen.findByText('The session ended (exit status 0).')).toBeInTheDocument();
    // The footer button (the dialog's X is also named Close).
    const close = screen.getAllByRole('button', { name: 'Close' }).at(-1);
    if (!close) {
      throw new Error('no close button');
    }
    await user.click(close);
    expect(onClose).toHaveBeenCalled();
    expect(sock.closed).toBe(true);
  });

  it('says why a terminal cannot be opened', async () => {
    mockApi({
      'GET /api/v1/me': makeMe(),
      'POST /api/v1/terminals': () =>
        problemResponse(403, 'forbidden', 'only enabled administrators can open a web terminal'),
    });
    renderInRouter(
      <WebTerminal serverId="srv_1" roleId="rol_1" title="ops (ops)" onClose={() => undefined} />,
    );
    expect(await screen.findByText('Cannot open the terminal')).toBeInTheDocument();
    expect(screen.getByText('only enabled administrators can open a web terminal')).toBeInTheDocument();
    expect(FakeSocket.last).toBeUndefined();
  });

  it('builds the stream URL for http and https pages', () => {
    expect(streamURL({ protocol: 'https:', host: 'hp.example.com' }, '/p', 'a b')).toBe(
      'wss://hp.example.com/p?ticket=a%20b',
    );
    expect(streamURL({ protocol: 'http:', host: 'localhost:8080' }, '/p', 't')).toBe(
      'ws://localhost:8080/p?ticket=t',
    );
  });
});
