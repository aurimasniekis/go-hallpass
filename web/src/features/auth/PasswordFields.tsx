import { Form, Input } from 'antd';

import { validatePasswordLength } from './password';

/** New password + confirmation fields with the PLAN §12.2 length rule. Field names: `password`, `confirm`. */
export function NewPasswordFields({
  name = 'password',
  label = 'Password',
}: {
  name?: string;
  label?: string;
}) {
  return (
    <>
      <Form.Item
        label={label}
        name={name}
        extra="12 to 1024 bytes. Long passphrases are encouraged."
        rules={[
          { required: true, message: 'Choose a password' },
          {
            validator: (_rule, value: unknown) => {
              const problem = typeof value === 'string' ? validatePasswordLength(value) : null;
              return problem ? Promise.reject(new Error(problem)) : Promise.resolve();
            },
          },
        ]}
      >
        <Input.Password autoComplete="new-password" />
      </Form.Item>
      <Form.Item
        label="Confirm password"
        name="confirm"
        dependencies={[name]}
        rules={[
          { required: true, message: 'Repeat the password' },
          ({ getFieldValue }) => ({
            validator: (_rule, value: unknown) =>
              value === getFieldValue(name)
                ? Promise.resolve()
                : Promise.reject(new Error('Passwords do not match')),
          }),
        ]}
      >
        <Input.Password autoComplete="new-password" />
      </Form.Item>
    </>
  );
}
