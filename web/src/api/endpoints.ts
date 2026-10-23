import type { paths } from './schema.gen';
import type { RequestOptions } from './client';

/**
 * Type-level helpers that bind API calls to the generated OpenAPI `paths` (api/openapi.yaml).
 *
 * `ApiPath<'get'>` is every `/api/v1/...` path with a GET operation; `PathParamsOf`, `QueryOf`, `BodyOf`
 * and `ResponseOf` extract the operation's path parameters, query parameters, JSON request body and
 * JSON success body. A path, method, parameter or body that the spec does not define fails `tsc`.
 */

export type HttpVerb = 'get' | 'post' | 'put' | 'patch' | 'delete';

type ApiPrefixed = Extract<keyof paths, `/api/v1/${string}`>;

/** Paths under `/api/v1` that define `method`. */
export type ApiPath<M extends HttpVerb> = {
  [P in ApiPrefixed]: [NonNullable<paths[P][M]>] extends [never] ? never : P;
}[ApiPrefixed];

export type Operation<P extends ApiPrefixed, M extends HttpVerb> = NonNullable<paths[P][M]>;

type IsNever<T> = [T] extends [never] ? true : false;

/** `{ id: string }` for `/agents/{id}`; `never` for paths without parameters. */
export type PathParamsOf<O> = O extends { parameters: { path: infer X } }
  ? IsNever<X> extends true
    ? never
    : NonNullable<X>
  : never;

export type QueryOf<O> = O extends { parameters: { query?: infer Q } }
  ? IsNever<Q> extends true
    ? never
    : NonNullable<Q>
  : never;

export type BodyOf<O> = O extends { requestBody?: { content: { 'application/json': infer B } } } ? B : never;

type SuccessStatus = 200 | 201 | 202 | 204;

/** JSON body of the operation's success response(s); `undefined` for 204. */
export type ResponseOf<O> = O extends { responses: infer R }
  ? {
      [K in keyof R & SuccessStatus]: R[K] extends { content: { 'application/json': infer J } }
        ? J
        : undefined;
    }[keyof R & SuccessStatus]
  : never;

type ParamsArg<O> = IsNever<PathParamsOf<O>> extends true ? { path?: undefined } : { path: PathParamsOf<O> };
type QueryArg<O> = IsNever<QueryOf<O>> extends true ? { query?: undefined } : { query?: QueryOf<O> };
type BodyArg<O> = IsNever<BodyOf<O>> extends true ? { body?: undefined } : { body?: BodyOf<O> };

export type CallOptions<P extends ApiPrefixed, M extends HttpVerb> = ParamsArg<Operation<P, M>> &
  QueryArg<Operation<P, M>> &
  BodyArg<Operation<P, M>> &
  Omit<RequestOptions, 'method' | 'body' | 'query'>;

/**
 * Replaces `{name}` segments with URL-encoded values and strips the `/api/v1` prefix (the client's
 * base URL). Throws on a missing parameter rather than calling a wrong URL.
 */
export function buildApiPath(template: string, params: Record<string, string | number> | undefined): string {
  const rel = template.startsWith('/api/v1') ? template.slice('/api/v1'.length) : template;
  return rel.replace(/\{([^}]+)\}/g, (_m, name: string) => {
    const value = params?.[name];
    if (value === undefined || value === '') {
      throw new Error(`missing path parameter "${name}" for ${template}`);
    }
    return encodeURIComponent(String(value));
  });
}
