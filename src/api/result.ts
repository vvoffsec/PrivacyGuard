export interface ApiSuccess<T> {
  readonly ok: true;
  readonly data: T;
}

export interface ApiErrorBody {
  readonly code: string;
  readonly message: string;
  readonly details?: unknown;
}

export interface ApiError {
  readonly ok: false;
  readonly error: ApiErrorBody;
}

export type ApiResult<T> = ApiSuccess<T> | ApiError;

export function apiSuccess<T>(data: T): ApiSuccess<T> {
  return Object.freeze({ ok: true as const, data });
}

export function apiError(code: string, message: string, details?: unknown): ApiError {
  return Object.freeze({
    ok: false as const,
    error: Object.freeze({ code, message, details }),
  });
}
