import { FastifyReplyWrap } from "../type/backend.type";

export type CookieSetOptions = {
    name: string;
    value: string;
    path: string;
    domain: string;
    maxAge?: number;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "strict" | "lax" | "none";
};

export type CookieClearOptions = {
    name: string;
    path: string;
    domain: string;
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: "strict" | "lax" | "none";
};

export default class CookieUtils {
    public static setCookie(
        reply: FastifyReplyWrap,
        options: CookieSetOptions
    ): FastifyReplyWrap {
        return reply.setCookie(options.name, options.value, {
            httpOnly: options.httpOnly ?? true,
            secure: options.secure ?? true,
            path: options.path,
            sameSite: options.sameSite ?? "strict",
            domain: options.domain,
            maxAge: options.maxAge
        });
    }

    public static clearCookie(
        reply: FastifyReplyWrap,
        options: CookieClearOptions
    ): FastifyReplyWrap {
        return reply.clearCookie(options.name, {
            httpOnly: options.httpOnly ?? true,
            secure: options.secure ?? true,
            path: options.path,
            sameSite: options.sameSite ?? "strict",
            domain: options.domain
        });
    }

    /**
     * From set-cookie string return a structured Map
     * @param cookies
     * @returns
     */
    public static parseSetCookie(
        cookies: string
    ): Map<string, Map<CookieProperty, string>> {
        const cookieMap = new Map<string, Map<CookieProperty, string>>();

        cookies.split(", ").forEach((cookie) => {
            const [keyValue, ...attributes] = cookie.split("; ");
            const [key, value] = keyValue.split("=");

            const attrMap = new Map<CookieProperty, string>();
            attributes.forEach((attr) => {
                const [attrKey, attrValue] = attr.split("=");
                attrMap.set(attrKey as CookieProperty, attrValue || "");
            });

            cookieMap.set(key, new Map([["value", value], ...attrMap]));
        });

        return cookieMap;
    }
}
type CookieProperty =
    | "value"
    | "Domain"
    | "Path"
    | "HttpOnly"
    | "Secure"
    | "SameSite";
