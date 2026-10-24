import { Alert, Form, Input, InputNumber, Switch } from 'antd';

import { TagsInput } from '../../ds/TagsInput';

/** Server create/edit fields. `showAddress` is false when the caller cannot see the address. */
export function ServerFormFields({ mode, showAddress }: { mode: 'create' | 'edit'; showAddress: boolean }) {
  return (
    <>
      <Form.Item
        label="Alias"
        name="alias"
        rules={[{ required: true, message: 'Enter an alias' }]}
        extra="Agents address the server by this alias (e.g. ssh hallpass connect db1)."
      >
        <Input autoComplete="off" spellCheck={false} maxLength={64} />
      </Form.Item>
      <Form.Item label="Display name" name="display_name">
        <Input maxLength={128} />
      </Form.Item>
      <Form.Item
        label="Description"
        name="description"
        extra="Informational only. Descriptions and labels never grant or restrict access; policy decides."
      >
        <Input.TextArea rows={2} maxLength={2000} />
      </Form.Item>
      <Form.Item label="Environment" name="environment">
        <Input maxLength={64} placeholder="production" />
      </Form.Item>
      {showAddress ? (
        <div style={{ display: 'flex', gap: 12 }}>
          <Form.Item
            label="Address"
            name="address"
            style={{ flex: 1 }}
            rules={
              mode === 'create' ? [{ required: true, message: 'Enter the host name or IP address' }] : []
            }
            extra="The gateway connects here; egress rules apply."
          >
            <Input autoComplete="off" spellCheck={false} />
          </Form.Item>
          <Form.Item label="Port" name="port">
            <InputNumber min={1} max={65535} placeholder="22" />
          </Form.Item>
        </div>
      ) : (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title="The address is hidden"
          description="Viewing or changing a destination address needs the inventory.address.read permission."
        />
      )}
      <Form.Item label="Enabled" name="enabled" valuePropName="checked">
        <Switch />
      </Form.Item>
      <Form.Item label="Groups" name="groups">
        <TagsInput aria-label="Groups" placeholder="Add group and press Enter" />
      </Form.Item>
      <Form.Item label="Labels" name="labels" extra="key=value pairs used by policy selectors.">
        <TagsInput aria-label="Labels" placeholder="env=prod" />
      </Form.Item>
      <Form.Item label="Metadata" name="metadata" extra="Free-form key=value notes. Not used by policy.">
        <TagsInput aria-label="Metadata" placeholder="owner=team-db" />
      </Form.Item>
    </>
  );
}
