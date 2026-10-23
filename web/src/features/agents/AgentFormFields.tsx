import { Form, Input, Switch } from 'antd';

import { TagsInput } from '../../ds/TagsInput';

/** Fields of the agent create/edit forms (names match AgentFormValues). */
export function AgentFormFields({ mode }: { mode: 'create' | 'edit' }) {
  return (
    <>
      <Form.Item
        label="Name"
        name="name"
        rules={[{ required: true, message: 'Enter a name' }]}
        extra="Agents use this name; it appears in requests and audit records."
      >
        <Input autoComplete="off" spellCheck={false} maxLength={128} />
      </Form.Item>
      <Form.Item label="Description" name="description">
        <Input.TextArea rows={2} maxLength={2000} />
      </Form.Item>
      {mode === 'create' ? (
        <Form.Item label="Enabled" name="enabled" valuePropName="checked">
          <Switch />
        </Form.Item>
      ) : null}
      <Form.Item
        label="Source CIDRs"
        name="source_cidrs"
        extra="Optional. When set, the agent may connect only from these networks (e.g. 10.0.0.0/8)."
      >
        <TagsInput aria-label="Source CIDRs" placeholder="Add CIDR and press Enter" />
      </Form.Item>
      <Form.Item label="Groups" name="groups" extra="Groups are created when first assigned.">
        <TagsInput aria-label="Groups" placeholder="Add group and press Enter" />
      </Form.Item>
      <Form.Item label="Labels" name="labels" extra="key=value pairs used by policy selectors.">
        <TagsInput aria-label="Labels" placeholder="env=prod" />
      </Form.Item>
      {mode === 'create' ? (
        <Form.Item
          label="Public keys"
          name="public_keys"
          extra="Optional. One authorized_keys line per line. More keys can be added later."
        >
          <Input.TextArea
            rows={3}
            spellCheck={false}
            className="hp-mono"
            placeholder="ssh-ed25519 AAAA… agent@host"
          />
        </Form.Item>
      ) : null}
    </>
  );
}
