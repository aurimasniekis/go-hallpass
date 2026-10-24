import { Form, InputNumber } from 'antd';

/** How many distinct approvers a request for this role needs (shared by SSH roles and git access profiles). */
export function ApprovalsRequiredField() {
  return (
    <Form.Item
      label="Approvers needed"
      name="approvals_required"
      rules={[{ required: true, type: 'integer', min: 1, max: 5, message: 'Between 1 and 5' }]}
      extra="Distinct approvers who must approve each request. Above 1, requests are never approved automatically by policy, and any one denial ends the request."
    >
      <InputNumber min={1} max={5} precision={0} aria-label="Approvers needed" />
    </Form.Item>
  );
}
