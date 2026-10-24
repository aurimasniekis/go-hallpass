import { Checkbox, Form, Input, Switch } from 'antd';

import { DurationInput } from '../../ds/DurationInput';
import { TagsInput } from '../../ds/TagsInput';
import type { GitProfileFormValues } from './gitForm';

// Patterns contain commas inside braces ({api,web}), so tokens are split on whitespace only.
const PATTERN_SEPARATORS = [' ', '\n'];

const PATTERN_HELP = (
  <>
    <code className="hp-mono">*</code> matches within one path segment, <code className="hp-mono">**</code>{' '}
    across segments, <code className="hp-mono">?</code> one character and{' '}
    <code className="hp-mono">{'{a,b}'}</code> either alternative. Press Enter after each pattern.
  </>
);

/** Create/edit fields of a git access profile. */
export function GitProfileFields() {
  const write = Form.useWatch<boolean | undefined>('write');
  return (
    <>
      <Form.Item
        label="Name"
        name="alias"
        rules={[{ required: true, message: 'Enter a name' }]}
        extra="Agents see this name and can request it explicitly, e.g. acme-push."
      >
        <Input maxLength={63} />
      </Form.Item>
      <Form.Item label="Description" name="description">
        <Input maxLength={200} />
      </Form.Item>
      <Form.Item
        label="Repositories"
        name="repos"
        rules={[{ required: true, type: 'array', min: 1, message: 'Add at least one repository pattern' }]}
        extra={
          <>
            Paths without <code className="hp-mono">.git</code>, matched case-insensitively, e.g.{' '}
            <code className="hp-mono">acme/{'{api,web}'}</code> or <code className="hp-mono">acme/*</code>.{' '}
            {PATTERN_HELP}
          </>
        }
      >
        <TagsInput
          aria-label="Repositories"
          tokenSeparators={PATTERN_SEPARATORS}
          placeholder="acme/{api,web}"
        />
      </Form.Item>
      <Form.Item name="write" valuePropName="checked">
        <Checkbox>Allow pushing (otherwise clone and fetch only)</Checkbox>
      </Form.Item>
      {write ? (
        <>
          <Form.Item
            label="Branches agents may create and update"
            name="branches"
            rules={[{ required: true, type: 'array', min: 1, message: 'Add at least one branch pattern' }]}
            extra={
              <>
                Relative to <code className="hp-mono">refs/heads/</code>, e.g.{' '}
                <code className="hp-mono">agent/**</code>. Pushes to any other branch are refused before they
                reach the host.
              </>
            }
          >
            <TagsInput
              aria-label="Allowed branches"
              tokenSeparators={PATTERN_SEPARATORS}
              placeholder="agent/**"
            />
          </Form.Item>
          <Form.Item
            label="Protected branches"
            name="protected_branches"
            extra="Never created, updated or deleted, even if an allowed pattern matches them."
          >
            <TagsInput aria-label="Protected branches" tokenSeparators={PATTERN_SEPARATORS} />
          </Form.Item>
          <Form.Item
            label="Tags agents may create"
            name="tags"
            extra="Existing tags are never moved or deleted. Leave empty to refuse all tag pushes."
          >
            <TagsInput aria-label="Allowed tags" tokenSeparators={PATTERN_SEPARATORS} placeholder="v*-rc.*" />
          </Form.Item>
          <Form.Item label="Branch deletion" name="allow_delete" valuePropName="checked">
            <Switch aria-label="Allow deleting allowed branches" />
          </Form.Item>
          <Form.Item
            label="Force-push"
            name="allow_force_push"
            valuePropName="checked"
            extra="Off: HallPass checks the pushed commits and refuses any branch update it cannot prove is a fast-forward."
          >
            <Switch aria-label="Allow force-push" />
          </Form.Item>
        </>
      ) : null}
      <Form.Item label="Default access duration" name="default_duration" rules={[{ required: true }]}>
        <DurationInput aria-label="Default duration" minSeconds={60} />
      </Form.Item>
      <Form.Item label="Maximum access duration" name="max_duration" rules={[{ required: true }]}>
        <DurationInput aria-label="Maximum duration" minSeconds={60} />
      </Form.Item>
    </>
  );
}

export type { GitProfileFormValues };
