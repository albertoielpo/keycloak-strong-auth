import { ForbiddenException } from "@nestjs/common";
import { ErrorEnum } from "../../common/enum/error.enum";
import { JwtTokenInfo } from "../type/backend.type";

export default class Base64Utils {
    private static b64DecodeUnicode(str: string): string {
        return decodeURIComponent(
            atob(str).replace(/(.)/g, (m, p) => {
                let code = p.charCodeAt(0).toString(16).toUpperCase();
                if (code.length < 2) {
                    code = `0${code}`;
                }
                return `%${code}`;
            })
        );
    }

    /**
     * Decode a base64 string
     * Native implementation with atob fallback
     *
     * @param str
     * @returns
     */
    public static base64UrlDecode(str: string): string {
        let output = str.replace(/-/g, "+").replace(/_/g, "/");
        switch (output.length % 4) {
            case 0:
                break;
            case 2:
                output += "==";
                break;
            case 3:
                output += "=";
                break;
            default:
                throw new Error("base64 string is not of the correct length");
        }
        try {
            return Base64Utils.b64DecodeUnicode(output);
        } catch (err) {
            return atob(output);
        }
    }

    public static getDecodeXUserInfo(b64Body: string): JwtTokenInfo {
        try {
            return JSON.parse(
                Base64Utils.base64UrlDecode(b64Body)
            ) as JwtTokenInfo;
        } catch (error) {
            throw new ForbiddenException(ErrorEnum.INVALID_TOKEN);
        }
    }

    public static isTokenExpired(jwtToken: string): boolean {
        try {
            const jsonBody = Base64Utils.getUserInfoFromAccessToken(jwtToken);
            return Math.floor(Date.now() / 1000) >= (Number(jsonBody.exp) || 0);
        } catch (error) {
            throw new ForbiddenException(ErrorEnum.INVALID_TOKEN);
        }
    }

    public static getUserInfoFromAccessToken(jwtToken: string): JwtTokenInfo {
        const b64Body = jwtToken.split(".")[1];
        return Base64Utils.getDecodeXUserInfo(b64Body);
    }
}
