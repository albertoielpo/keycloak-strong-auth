import { FastifyReplyWrap } from "../type/backend.type";
import CookieUtils, {
    CookieClearOptions,
    CookieSetOptions
} from "./cookie.utils";

describe("CookieUtils", () => {
    describe("setCookie", () => {
        it("should set the cookie with the provided options and default values for optional fields", () => {
            const mockReply = {
                setCookie: jest.fn().mockReturnThis()
            } as unknown as FastifyReplyWrap;

            const options: CookieSetOptions = {
                name: "testCookie",
                value: "testValue",
                path: "/",
                domain: "example.com",
                maxAge: 3600
            };

            const result = CookieUtils.setCookie(mockReply, options);

            expect(mockReply.setCookie).toHaveBeenCalledWith(
                options.name,
                options.value,
                {
                    httpOnly: true,
                    secure: true,
                    path: options.path,
                    sameSite: "strict",
                    domain: options.domain,
                    maxAge: options.maxAge
                }
            );
            expect(result).toBe(mockReply);
        });

        it("should set the cookie with the provided options overriding default values", () => {
            const mockReply = {
                setCookie: jest.fn().mockReturnThis()
            } as unknown as FastifyReplyWrap;

            const options: CookieSetOptions = {
                name: "testCookie",
                value: "testValue",
                path: "/",
                domain: "example.com",
                maxAge: 3600,
                httpOnly: false,
                secure: false,
                sameSite: "lax"
            };

            const result = CookieUtils.setCookie(mockReply, options);

            expect(mockReply.setCookie).toHaveBeenCalledWith(
                options.name,
                options.value,
                {
                    httpOnly: false,
                    secure: false,
                    path: options.path,
                    sameSite: "lax",
                    domain: options.domain,
                    maxAge: options.maxAge
                }
            );
            expect(result).toBe(mockReply);
        });
    });

    describe("clearCookie", () => {
        it("should clear the cookie with the provided options and default values for optional fields", () => {
            const mockReply = {
                clearCookie: jest.fn().mockReturnThis()
            } as unknown as FastifyReplyWrap;

            const options: CookieClearOptions = {
                name: "testCookie",
                path: "/",
                domain: "example.com"
            };

            const result = CookieUtils.clearCookie(mockReply, options);

            expect(mockReply.clearCookie).toHaveBeenCalledWith(options.name, {
                httpOnly: true,
                secure: true,
                path: options.path,
                sameSite: "strict",
                domain: options.domain
            });
            expect(result).toBe(mockReply);
        });

        it("should clear the cookie with the provided options overriding default values", () => {
            const mockReply = {
                clearCookie: jest.fn().mockReturnThis()
            } as unknown as FastifyReplyWrap;

            const options: CookieClearOptions = {
                name: "testCookie",
                path: "/",
                domain: "example.com",
                httpOnly: false,
                secure: false,
                sameSite: "lax"
            };

            const result = CookieUtils.clearCookie(mockReply, options);

            expect(mockReply.clearCookie).toHaveBeenCalledWith(options.name, {
                httpOnly: false,
                secure: false,
                path: options.path,
                sameSite: "lax",
                domain: options.domain
            });
            expect(result).toBe(mockReply);
        });
    });

    describe("CookieParser.parseSetCookie", () => {
        it("parses a single Set-Cookie string correctly", () => {
            const cookies =
                "sessionId=abc123; Domain=example.com; Path=/; HttpOnly";
            const result = CookieUtils.parseSetCookie(cookies);

            expect(result.size).toBe(1);
            expect(result.has("sessionId")).toBe(true);

            const sessionIdAttributes = result.get("sessionId")!;
            expect(sessionIdAttributes.get("value")).toBe("abc123");
            expect(sessionIdAttributes.get("Domain")).toBe("example.com");
            expect(sessionIdAttributes.get("Path")).toBe("/");
            expect(sessionIdAttributes.get("HttpOnly")).toBe("");
        });

        it("parses multiple cookies in a single Set-Cookie header", () => {
            const cookies =
                "sessionId=abc123; Domain=example.com, token=xyz456; Path=/secure; Secure; HttpOnly";
            const result = CookieUtils.parseSetCookie(cookies);

            expect(result.size).toBe(2);
            expect(result.has("sessionId")).toBe(true);
            expect(result.has("token")).toBe(true);

            const sessionIdAttributes = result.get("sessionId")!;
            expect(sessionIdAttributes.get("value")).toBe("abc123");
            expect(sessionIdAttributes.get("Domain")).toBe("example.com");

            const tokenAttributes = result.get("token")!;
            expect(tokenAttributes.get("value")).toBe("xyz456");
            expect(tokenAttributes.get("Path")).toBe("/secure");
            expect(tokenAttributes.get("Secure")).toBe("");
            expect(tokenAttributes.get("HttpOnly")).toBe("");
        });

        it("handles cookies with missing attributes correctly", () => {
            const cookies = "userId=789xyz";
            const result = CookieUtils.parseSetCookie(cookies);

            expect(result.size).toBe(1);
            expect(result.has("userId")).toBe(true);

            const userIdAttributes = result.get("userId")!;
            expect(userIdAttributes.get("value")).toBe("789xyz");
            expect(userIdAttributes.size).toBe(1); // Only "value" is present
        });

        it("handles malformed cookies gracefully", () => {
            const cookies = "invalidcookie";
            const result = CookieUtils.parseSetCookie(cookies);

            expect(result.size).toBe(1);
            expect(result.has("invalidcookie")).toBe(true);

            const invalidCookieAttributes = result.get("invalidcookie")!;
            expect(invalidCookieAttributes.get("value")).toBe(undefined);
        });
    });
});
