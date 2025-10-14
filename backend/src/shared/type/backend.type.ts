export type StatusCodeOk = "OK";
export type StatusCodeError = "FAIL" | "ERROR";

export type HttpExceptionFunctionType = {
    getStatus: Function;
    getResponse: Function;
};

// trace == verbose, debug == debug, info == log, warn == warn, error == error
export type PinoLogLevel = "trace" | "debug" | "info" | "warn" | "error";

export type FastifyReplyWrap = {
    status: Function;
    header: Function;
    send: Function;
    setCookie: Function;
    clearCookie: Function;
};

export type AnyString = string;

/**
 * JwtTokenInfo represent the BODY of the JwtToken
 * header authentication: <HEAD>.<BODY>.<SIGNATURE>
 * header x-userinfo only <BODY>
 */
export type JwtTokenInfo = {
    exp: number;
    iat: number;
    iss: string;
    email: string;
};

// This is necessary because @nestjs/platform-fastify (11) and @fastify/cookie (11) are compatible with fastify (5)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type FastifyCookie = any;

// Cookie names availables
export type CookieNames = { token?: string; refresh?: string };
