import type { ApiResult } from "./result.js";
import { apiError } from "./result.js";

export type ApiRoute =
  | "ingress.evaluate"
  | "tool.authorize"
  | "memory.write"
  | "decision.explain";

export type ApiHandler = (request: unknown) => ApiResult<unknown>;

export interface ApiRouter {
  handle(route: ApiRoute, request: unknown): ApiResult<unknown>;
}

export function createInProcessTransport(
  handlers: Readonly<Record<ApiRoute, ApiHandler>>,
): ApiRouter {
  return Object.freeze({
    handle(route: ApiRoute, request: unknown): ApiResult<unknown> {
      const handler = handlers[route] as ApiHandler | undefined;
      if (!handler) {
        return apiError("UNKNOWN_ROUTE", `No handler registered for route: ${route}`);
      }

      try {
        return handler(request);
      } catch {
        // Fail closed: unhandled exceptions become deny-equivalent errors
        return apiError(
          "INTERNAL_ERROR",
          "An unexpected error occurred; failing closed.",
        );
      }
    },
  });
}
