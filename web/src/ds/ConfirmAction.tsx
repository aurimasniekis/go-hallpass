import { Alert, Button, Input, Modal, type ButtonProps } from 'antd';
import { useId, useState, type ReactNode } from 'react';

import { errorMessage } from '../api/errors';

export interface ConfirmActionProps<T> {
  /** Trigger button content. */
  label: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  /**
   * When set, the operator must type this exact phrase before confirming (HP-UI-010: lockdown,
   * delete server, revoke all).
   */
  typedConfirmation?: string;
  /** Performs the mutation. The dialog stays open, showing progress, until the server answers. */
  onConfirm: () => Promise<T>;
  /** Called only after the server confirmed success (HP-UI-012: no optimistic success). */
  onSuccess?: (result: T) => void;
  disabled?: boolean;
  buttonProps?: Omit<ButtonProps, 'onClick' | 'danger' | 'disabled'>;
}

export function ConfirmAction<T>({
  label,
  title,
  description,
  confirmLabel = 'Confirm',
  danger = true,
  typedConfirmation,
  onConfirm,
  onSuccess,
  disabled,
  buttonProps,
}: ConfirmActionProps<T>) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inputId = useId();

  const phraseOk = typedConfirmation === undefined || typed === typedConfirmation;

  const close = () => {
    if (pending) {
      return;
    }
    setOpen(false);
    setTyped('');
    setError(null);
  };

  const confirm = async () => {
    if (!phraseOk || pending) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      const result = await onConfirm();
      setOpen(false);
      setTyped('');
      onSuccess?.(result);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <Button
        {...buttonProps}
        danger={danger}
        disabled={disabled}
        onClick={() => {
          setOpen(true);
        }}
      >
        {label}
      </Button>
      <Modal
        open={open}
        title={title}
        onCancel={close}
        mask={{ closable: !pending }}
        keyboard={!pending}
        closable={!pending}
        destroyOnHidden
        footer={[
          <Button key="cancel" onClick={close} disabled={pending}>
            Cancel
          </Button>,
          <Button
            key="confirm"
            type="primary"
            danger={danger}
            loading={pending}
            disabled={!phraseOk}
            onClick={() => {
              void confirm();
            }}
          >
            {confirmLabel}
          </Button>,
        ]}
      >
        {description ? <div style={{ marginBottom: 12 }}>{description}</div> : null}
        {typedConfirmation !== undefined ? (
          <div>
            <label htmlFor={inputId}>
              Type <code className="hp-mono">{typedConfirmation}</code> to confirm
            </label>
            <Input
              id={inputId}
              value={typed}
              autoComplete="off"
              spellCheck={false}
              disabled={pending}
              onChange={(e) => {
                setTyped(e.target.value);
              }}
              onPressEnter={() => {
                void confirm();
              }}
              style={{ marginTop: 4 }}
            />
          </div>
        ) : null}
        {error !== null ? (
          <Alert
            style={{ marginTop: 12 }}
            type="error"
            showIcon
            title="The action failed"
            description={errorMessage(error)}
          />
        ) : null}
      </Modal>
    </>
  );
}
