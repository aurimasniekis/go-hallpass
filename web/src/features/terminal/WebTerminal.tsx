import '@xterm/xterm/css/xterm.css';

import { Terminal } from '@xterm/xterm';
import { Alert, Button, Modal, Space, Tag } from 'antd';
import { useEffect, useRef, useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { Countdown } from '../../ds/Countdown';
import { LoadingState } from '../../ds/states';
import { hardenTerminal, SAFE_TERMINAL_OPTIONS } from '../../ds/terminal';

/** Columns and rows of the web terminal (fits the dialog at the default font size). */
export const TERMINAL_COLS = 120;
export const TERMINAL_ROWS = 32;

interface Opened {
  grant_id: string;
  session_id: string;
  expires_at: string;
  ticket: string;
  stream_path: string;
}

/** ws(s)://host + path for the current page origin. */
export function streamURL(
  location: Pick<Location, 'protocol' | 'host'>,
  path: string,
  ticket: string,
): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}${path}?ticket=${encodeURIComponent(ticket)}`;
}

type State =
  | { kind: 'opening' }
  | { kind: 'connected'; opened: Opened }
  | { kind: 'ended'; opened?: Opened; message: string; error?: boolean };

/**
 * A recorded web terminal on a server role (ADR-0055); mount it to open one. It opens the grant (recent sign-in and
 * MFA), connects the WebSocket with the single-use ticket, and ends the grant when closed. Output comes from the
 * destination and is rendered with the same hardening as replay (no links, no clipboard or title escapes); input goes
 * to the shell.
 */
export function WebTerminal({
  serverId,
  roleId,
  title,
  onClose,
}: {
  serverId: string;
  roleId: string;
  title: string;
  onClose: () => void;
}) {
  const host = useRef<HTMLDivElement | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const [state, setState] = useState<State>({ kind: 'opening' });

  useEffect(() => {
    const alive = { current: true };
    const term = new Terminal({
      ...SAFE_TERMINAL_OPTIONS,
      disableStdin: false,
      cursorBlink: true,
      cursorStyle: 'block',
      cols: TERMINAL_COLS,
      rows: TERMINAL_ROWS,
    });
    const disposables = hardenTerminal(term);
    void (async () => {
      let opened: Opened;
      try {
        opened = await api.call('post', '/api/v1/terminals', {
          body: { server_id: serverId, role_id: roleId },
        });
      } catch (e) {
        if (alive.current) {
          setState({ kind: 'ended', message: errorMessage(e), error: true });
        }
        return;
      }
      if (!alive.current) {
        return;
      }
      setState({ kind: 'connected', opened });
      const socket = new WebSocket(streamURL(window.location, opened.stream_path, opened.ticket));
      socket.binaryType = 'arraybuffer';
      ws.current = socket;
      socket.onopen = () => {
        socket.send(JSON.stringify({ type: 'resize', cols: TERMINAL_COLS, rows: TERMINAL_ROWS }));
        term.focus();
      };
      socket.onmessage = (ev: MessageEvent<ArrayBuffer | string>) => {
        if (typeof ev.data !== 'string') {
          term.write(new Uint8Array(ev.data));
          return;
        }
        try {
          const msg = JSON.parse(ev.data) as { type: string; status?: number; signal?: string };
          if (msg.type === 'exit') {
            const how = msg.signal ? `signal ${msg.signal}` : `exit status ${String(msg.status ?? 0)}`;
            setState({ kind: 'ended', opened, message: `The session ended (${how}).` });
          }
        } catch {
          term.write(ev.data);
        }
      };
      socket.onclose = () => {
        setState((s) =>
          s.kind === 'ended'
            ? s
            : { kind: 'ended', opened, message: 'Disconnected. The terminal is closed.' },
        );
      };
      term.onData((data) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'input', data }));
        }
      });
    })();
    // The dialog content may mount a frame after the effect runs.
    const attach = () => {
      if (host.current && !term.element) {
        term.open(host.current);
      }
    };
    attach();
    const frame = requestAnimationFrame(attach);
    return () => {
      alive.current = false;
      cancelAnimationFrame(frame);
      ws.current?.close();
      ws.current = null;
      for (const d of disposables) {
        d.dispose();
      }
      term.dispose();
    };
  }, [serverId, roleId]);

  const opened =
    state.kind === 'connected' ? state.opened : state.kind === 'ended' ? state.opened : undefined;
  return (
    <Modal
      open
      title={
        <Space wrap>
          <span>{title}</span>
          <Tag color="red">Recorded</Tag>
          {opened && state.kind === 'connected' ? (
            <span>
              Ends in <Countdown deadline={opened.expires_at} />
            </span>
          ) : null}
        </Space>
      }
      width={1040}
      destroyOnHidden
      mask={{ closable: false }}
      onCancel={onClose}
      footer={
        <Button
          danger={state.kind === 'connected'}
          onClick={() => {
            ws.current?.close();
            onClose();
          }}
        >
          {state.kind === 'connected' ? 'Disconnect' : 'Close'}
        </Button>
      }
    >
      {state.kind === 'opening' ? <LoadingState /> : null}
      {state.kind === 'ended' ? (
        <Alert
          type={state.error ? 'error' : 'info'}
          showIcon
          style={{ marginBottom: 12 }}
          title={state.error ? 'Cannot open the terminal' : 'Session ended'}
          description={state.message}
        />
      ) : null}
      <div
        ref={host}
        role="application"
        aria-label={`Terminal: ${title}`}
        style={{ background: '#000', padding: 8, borderRadius: 4, overflow: 'auto' }}
      />
      <p style={{ margin: '8px 0 0', color: 'var(--hp-color-text-secondary, #666)' }}>
        Everything shown here is recorded and you are named in the audit log. Closing this window ends the
        session.
      </p>
    </Modal>
  );
}
