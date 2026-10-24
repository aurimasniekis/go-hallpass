import { Alert, Button, Input, Modal, type ButtonProps } from 'antd';
import { useId, useState, type ReactNode } from 'react';

import { errorMessage } from '../api/errors';
import { newIdempotencyKey } from '../lib/idempotency';

export interface ConfirmContext {
  /**
   * `Idempotency-Key` for this confirmation. Created when the dialog opens and reused if the operator
   * retries after a failure, so a request that reached the server is never applied twice (HP-API-006).
   */
  idempotencyKey: string;
}

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
  onConfirm: (context: ConfirmContext) => Promise<T>;
  /** Called only after the server confirmed success (HP-UI-012: no optimistic success). */
  onSuccess?: (result: T) => void;
  disabled?: boolean;
  /** Disables the confirm button (e.g. a required reason is still empty). */
  confirmDisabled?: boolean;
  /** Called when the dialog opens (reset embedded form state here). */
  onOpen?: () => void;
  buttonProps?: Omit<ButtonProps, 'onClick' | 'danger' | 'disabled'>;
  /**
   * Replaces the trigger button (e.g. a Switch that must not flip before the server confirms). Call
   * `open` to show the dialog; `label` and `buttonProps` are then unused.
   */
  renderTrigger?: (trigger: { open: () => void; disabled: boolean | undefined }) => ReactNode;
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
  confirmDisabled = false,
  onOpen,
  buttonProps,
  renderTrigger,
}: ConfirmActionProps<T>) {
  const [open, setOpen] = useState(false);
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);
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
    if (!phraseOk || pending || confirmDisabled) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      const result = await onConfirm({ idempotencyKey });
      setOpen(false);
      setTyped('');
      onSuccess?.(result);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  const openDialog = () => {
    if (disabled) {
      return;
    }
    setIdempotencyKey(newIdempotencyKey());
    onOpen?.();
    setOpen(true);
  };

  return (
    <>
      {renderTrigger ? (
        renderTrigger({ open: openDialog, disabled })
      ) : (
        <Button {...buttonProps} danger={danger} disabled={disabled} onClick={openDialog}>
          {label}
        </Button>
      )}
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
            disabled={!phraseOk || confirmDisabled}
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
