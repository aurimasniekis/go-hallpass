import type { FormInstance } from 'antd';

import { isApiError } from '../api/errors';

/**
 * Copies `validation_failed` field errors (`errors[].field`) onto matching antd form fields.
 * Returns true when at least one field received a message; the caller still shows the general error.
 * Field names may be dotted (`subjects.agents`); only the top-level name is matched.
 */
export function applyFieldErrors(
  form: Pick<FormInstance, 'setFields' | 'getFieldsValue'>,
  error: unknown,
): boolean {
  if (!isApiError(error)) {
    return false;
  }
  const known = new Set(Object.keys((form.getFieldsValue(true) ?? {}) as Record<string, unknown>));
  const fields = Object.entries(error.fields)
    .map(([key, messages]) => ({ name: key.split('.')[0] ?? key, errors: messages }))
    .filter((f) => known.has(f.name));
  if (fields.length > 0) {
    form.setFields(fields);
  }
  return fields.length > 0;
}
