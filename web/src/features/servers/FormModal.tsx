import { Alert, Button, Form, Modal, type FormInstance } from 'antd';
import { useState, type ReactNode } from 'react';

import { errorMessage } from '../../api/errors';
import { applyFieldErrors } from '../../lib/formErrors';
import { newIdempotencyKey } from '../../lib/idempotency';
import { conflictHint, LabelFormatError } from './formUtils';

export interface FormModalProps<V extends object> {
  open: boolean;
  title: ReactNode;
  okText: string;
  /** Accessible name of the form. */
  formLabel: string;
  initialValues?: Partial<V>;
  onCancel: () => void;
  /**
   * Performs the request. Resolve only after the server confirmed (HP-UI-012). The idempotency key is
   * created when the dialog opens and reused for retries from the same dialog (HP-API-006).
   */
  onSubmit: (values: V, ctx: { idempotencyKey: string }) => Promise<void>;
  children: ReactNode | ((form: FormInstance<V>) => ReactNode);
  width?: number;
  danger?: boolean;
}

function Body<V extends object>({
  okText,
  formLabel,
  initialValues,
  onCancel,
  onSubmit,
  children,
  danger,
}: Omit<FormModalProps<V>, 'open' | 'title' | 'width'>) {
  const [form] = Form.useForm<V>();
  const [idempotencyKey] = useState(newIdempotencyKey);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (values: V) => {
    setPending(true);
    setError(null);
    try {
      await onSubmit(values, { idempotencyKey });
    } catch (e) {
      if (e instanceof LabelFormatError) {
        setError(e);
      } else {
        applyFieldErrors(form, e);
        setError(e);
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<V>
      form={form}
      layout="vertical"
      requiredMark="optional"
      aria-label={formLabel}
      {...(initialValues ? { initialValues: initialValues } : {})}
      onFinish={(values) => {
        void submit(values);
      }}
    >
      {typeof children === 'function' ? children(form) : children}
      {error !== null ? (
        <Alert
          type="error"
          showIcon
          title={errorMessage(error)}
          description={conflictHint(error) ?? undefined}
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
        <Button onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="primary" danger={danger} htmlType="submit" loading={pending}>
          {okText}
        </Button>
      </div>
    </Form>
  );
}

/** Modal form whose state (values, error, idempotency key) is discarded when it closes. */
export function FormModal<V extends object>({ open, title, width = 560, ...rest }: FormModalProps<V>) {
  return (
    <Modal open={open} title={title} width={width} footer={null} destroyOnHidden onCancel={rest.onCancel}>
      {open ? <Body<V> {...rest} /> : null}
    </Modal>
  );
}
