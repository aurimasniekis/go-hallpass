import { Alert, Checkbox, Form, Input, InputNumber, Radio, Switch } from 'antd';

import { DurationInput } from '../../ds/DurationInput';
import { TagsInput } from '../../ds/TagsInput';
import { formatDuration } from '../../lib/format';
import {
  APPROVAL_CHANNELS,
  CAPABILITIES,
  RECORDING_MODES,
  roleFormProblems,
  type RoleFormValues,
} from './roleForm';

function check(field: keyof ReturnType<typeof roleFormProblems>) {
  return ({ getFieldsValue }: { getFieldsValue: (all: true) => unknown }) => ({
    validator: () => {
      const problem = roleFormProblems(getFieldsValue(true) as RoleFormValues)[field];
      return problem ? Promise.reject(new Error(problem)) : Promise.resolve();
    },
  });
}

/** Role create/edit fields. Durations are edited with DurationInput and stored as seconds. */
export function RoleFormFields() {
  const recordInput = Form.useWatch<boolean | undefined>('record_input');
  const maxDuration = Form.useWatch<number | null | undefined>('max_duration');
  return (
    <>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <Form.Item
          label="Alias"
          name="alias"
          style={{ flex: 1, minWidth: 180 }}
          rules={[{ required: true, message: 'Enter an alias' }]}
          extra="Agents request this role by alias."
        >
          <Input autoComplete="off" spellCheck={false} maxLength={64} />
        </Form.Item>
        <Form.Item
          label="Remote user"
          name="remote_user"
          style={{ flex: 1, minWidth: 180 }}
          rules={[{ required: true, message: 'Enter the destination login user' }]}
        >
          <Input autoComplete="off" spellCheck={false} maxLength={32} />
        </Form.Item>
      </div>
      <Form.Item label="Display name" name="display_name">
        <Input maxLength={128} />
      </Form.Item>
      <Form.Item
        label="Description"
        name="description"
        extra="Informational only; it does not restrict what the agent can run."
      >
        <Input.TextArea rows={2} maxLength={2000} />
      </Form.Item>
      <Form.Item
        label="Capabilities"
        name="capabilities"
        rules={[{ required: true, message: 'Choose capabilities' }, check('capabilities')]}
      >
        <Checkbox.Group options={CAPABILITIES.map((c) => ({ value: c.value, label: c.label }))} />
      </Form.Item>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <Form.Item
          label="Default duration"
          name="default_duration"
          dependencies={['max_duration']}
          rules={[{ required: true, message: 'Set a default duration' }, check('default_duration')]}
          extra="Used when the agent does not ask for a duration."
        >
          <DurationInput aria-label="Default duration" minSeconds={60} />
        </Form.Item>
        <Form.Item
          label="Maximum duration"
          name="max_duration"
          rules={[{ required: true, message: 'Set a maximum duration' }]}
          extra={
            maxDuration
              ? `Grants never exceed ${formatDuration(maxDuration)} (and the global cap).`
              : undefined
          }
        >
          <DurationInput aria-label="Maximum duration" minSeconds={60} />
        </Form.Item>
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <Form.Item label="Max concurrent channels" name="max_concurrent">
          <InputNumber min={1} max={10000} />
        </Form.Item>
        <Form.Item
          label="Max concurrent per agent"
          name="max_concurrent_per_agent"
          dependencies={['max_concurrent']}
          rules={[check('max_concurrent_per_agent')]}
        >
          <InputNumber min={1} max={10000} />
        </Form.Item>
      </div>
      <Form.Item label="Recording" name="recording_mode">
        <Radio.Group options={RECORDING_MODES.map((m) => ({ value: m.value, label: m.label }))} />
      </Form.Item>
      <Form.Item
        label="Record keyboard input"
        name="record_input"
        valuePropName="checked"
        extra="Off by default. Output is always recorded."
      >
        <Switch />
      </Form.Item>
      {recordInput ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          title="Input may contain secrets"
          description="Typed input (including passwords entered at prompts) will be stored in recordings. HallPass does not redact secrets."
        />
      ) : null}
      <Form.Item
        label="Approval channels"
        name="approval_channels"
        rules={[check('approval_channels')]}
        extra="Where approvers may decide requests for this role. Use web only for sensitive roles."
      >
        <Checkbox.Group options={APPROVAL_CHANNELS.map((c) => ({ value: c.value, label: c.label }))} />
      </Form.Item>
      <Form.Item
        label="Allowed environment variables"
        name="env_allow"
        extra="Names or prefixes ending in * that agents may pass (e.g. LANG, LC_*)."
      >
        <TagsInput aria-label="Allowed environment variables" placeholder="LC_*" />
      </Form.Item>
      <Form.Item label="Retention class" name="retention_class">
        <Input spellCheck={false} maxLength={32} placeholder="default" />
      </Form.Item>
      <Form.Item label="Labels" name="labels" extra="key=value pairs used by policy role selectors.">
        <TagsInput aria-label="Labels" placeholder="tier=app" />
      </Form.Item>
      <Form.Item label="Restriction notes" name="restriction_notes" extra="Shown to approvers. Not enforced.">
        <Input.TextArea rows={2} maxLength={2000} />
      </Form.Item>
      <Form.Item label="Enabled" name="enabled" valuePropName="checked">
        <Switch />
      </Form.Item>
    </>
  );
}
