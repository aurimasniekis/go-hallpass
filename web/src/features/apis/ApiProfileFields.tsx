import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { Button, Card, Form, Input, Select, Space } from 'antd';

import { DurationInput } from '../../ds/DurationInput';
import { TagsInput } from '../../ds/TagsInput';
import { ApprovalsRequiredField } from '../roles/ApprovalsRequiredField';
import { GRAPHQL_TYPES, METHODS, type ApiProfileFormValues, type ApiRuleFormValue } from './apiForm';

// Patterns contain commas inside braces ({api,web}), so tokens are split on whitespace only.
const PATTERN_SEPARATORS = [' ', '\n'];

const NEW_RULE: ApiRuleFormValue = { effect: 'allow', methods: ['GET'], hosts: [], paths: [], graphql: [] };

/** Create/edit fields of an API access profile: name, rules, approvals and durations. */
export function ApiProfileFields() {
  return (
    <>
      <Form.Item
        label="Name"
        name="alias"
        rules={[{ required: true, message: 'Enter a name' }]}
        extra="Agents see this name and request it explicitly, e.g. read or issues."
      >
        <Input maxLength={63} />
      </Form.Item>
      <Form.Item label="Description" name="description">
        <Input maxLength={200} />
      </Form.Item>
      <Form.Item
        label="Rules"
        extra={
          <>
            A request is allowed when an allow rule matches and no deny rule does. Empty fields match
            anything. Paths: <code className="hp-mono">*</code> is one segment,{' '}
            <code className="hp-mono">**</code> any number, <code className="hp-mono">{'{a,b}'}</code> either;
            press Enter after each pattern.
          </>
        }
      >
        <Form.List
          name="rules"
          rules={[
            {
              validator: (_, rules?: ApiRuleFormValue[]) =>
                (rules ?? []).some((r) => r.effect === 'allow')
                  ? Promise.resolve()
                  : Promise.reject(new Error('Add at least one allow rule')),
            },
          ]}
        >
          {(fields, { add, remove }, { errors }) => (
            <Space orientation="vertical" size={8} style={{ width: '100%' }}>
              {fields.map((field, i) => (
                <Card
                  key={field.key}
                  size="small"
                  title={`Rule ${i + 1}`}
                  extra={
                    <Button
                      size="small"
                      type="text"
                      icon={<DeleteOutlined />}
                      aria-label={`Remove rule ${i + 1}`}
                      onClick={() => {
                        remove(field.name);
                      }}
                    />
                  }
                >
                  <Space size={12} align="start" wrap>
                    <Form.Item label="Effect" name={[field.name, 'effect']}>
                      <Select
                        aria-label={`Rule ${i + 1} effect`}
                        style={{ width: 110 }}
                        options={[
                          { value: 'allow', label: 'Allow' },
                          { value: 'deny', label: 'Deny' },
                        ]}
                      />
                    </Form.Item>
                    <Form.Item label="Methods" name={[field.name, 'methods']}>
                      <Select
                        aria-label={`Rule ${i + 1} methods`}
                        mode="multiple"
                        allowClear
                        placeholder="Any"
                        style={{ minWidth: 220 }}
                        options={METHODS.map((m) => ({ value: m, label: m }))}
                      />
                    </Form.Item>
                    <Form.Item label="GraphQL operations" name={[field.name, 'graphql']}>
                      <Select
                        aria-label={`Rule ${i + 1} GraphQL operations`}
                        mode="multiple"
                        allowClear
                        placeholder="Not GraphQL"
                        style={{ minWidth: 200 }}
                        options={GRAPHQL_TYPES.map((t) => ({ value: t, label: t }))}
                      />
                    </Form.Item>
                  </Space>
                  <Form.Item label="Paths" name={[field.name, 'paths']}>
                    <TagsInput
                      aria-label={`Rule ${i + 1} paths`}
                      tokenSeparators={PATTERN_SEPARATORS}
                      placeholder="Any path, e.g. /repos/acme/**"
                    />
                  </Form.Item>
                  <Form.Item label="Hosts" name={[field.name, 'hosts']} style={{ marginBottom: 0 }}>
                    <TagsInput
                      aria-label={`Rule ${i + 1} hosts`}
                      tokenSeparators={PATTERN_SEPARATORS}
                      placeholder="Every host of the target"
                    />
                  </Form.Item>
                </Card>
              ))}
              <Button
                icon={<PlusOutlined />}
                onClick={() => {
                  add({ ...NEW_RULE });
                }}
              >
                Add rule
              </Button>
              <Form.ErrorList errors={errors} />
            </Space>
          )}
        </Form.List>
      </Form.Item>
      <ApprovalsRequiredField />
      <Form.Item label="Default access duration" name="default_duration" rules={[{ required: true }]}>
        <DurationInput aria-label="Default duration" minSeconds={60} />
      </Form.Item>
      <Form.Item label="Maximum access duration" name="max_duration" rules={[{ required: true }]}>
        <DurationInput aria-label="Maximum duration" minSeconds={60} />
      </Form.Item>
    </>
  );
}

export type { ApiProfileFormValues };
