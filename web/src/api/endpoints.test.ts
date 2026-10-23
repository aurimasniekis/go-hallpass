import { describe, expect, expectTypeOf, it } from 'vitest';

import type { ApiPath, BodyOf, Operation, PathParamsOf, QueryOf, ResponseOf } from './endpoints';
import type { AccessRequest, AgentKey, Decision, RequestPage } from './types';

/**
 * Compile-time checks: `pnpm typecheck` fails if the generated OpenAPI types and the helpers drift apart.
 * The runtime assertions only keep Vitest from reporting an empty suite.
 */
describe('endpoint typing', () => {
  it('derives parameters, bodies and responses from the spec', () => {
    type Approve = Operation<'/api/v1/requests/{id}/approve', 'post'>;
    expectTypeOf<PathParamsOf<Approve>>().toEqualTypeOf<{ id: string }>();
    expectTypeOf<BodyOf<Approve>>().toEqualTypeOf<{ duration?: number; comment?: string }>();
    expectTypeOf<ResponseOf<Approve>>().toEqualTypeOf<Decision>();

    type ListRequests = Operation<'/api/v1/requests', 'get'>;
    expectTypeOf<ResponseOf<ListRequests>>().toEqualTypeOf<RequestPage>();
    expectTypeOf<QueryOf<ListRequests>['state']>().toEqualTypeOf<AccessRequest['state'] | undefined>();
    expectTypeOf<PathParamsOf<ListRequests>>().toBeNever();

    type RevokeKey = Operation<'/api/v1/agents/{id}/keys/{kid}/revoke', 'post'>;
    expectTypeOf<PathParamsOf<RevokeKey>>().toEqualTypeOf<{ id: string; kid: string }>();
    expectTypeOf<ResponseOf<RevokeKey>>().toEqualTypeOf<AgentKey>();

    // 204 responses resolve to undefined.
    expectTypeOf<ResponseOf<Operation<'/api/v1/me/password', 'post'>>>().toEqualTypeOf<undefined>();

    // Only spec-defined methods are accepted per path.
    expectTypeOf<'/api/v1/requests'>().toExtend<ApiPath<'get'>>();
    expectTypeOf<'/api/v1/requests'>().not.toExtend<ApiPath<'post'>>();
    expectTypeOf<'/auth/oidc/{provider}/start'>().not.toExtend<ApiPath<'get'>>();

    expect(true).toBe(true);
  });
});
