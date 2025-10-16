import { HttpException } from "@nestjs/common";
import { ErrorEnum } from "../../common/enum/error.enum";
import Base64Utils from "./base64.utils";

describe("Base64Utils", () => {
    // Generic JWT token with expired timestamp (exp: 1715674724 = May 2024)
    const jwtTokenString =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Rfa2V5XzEyMyJ9.eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoidGVzdC11dWlkLTEyMzQtNTY3OC05YWJjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tL3JlYWxtcy90ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6InRlc3QtdXNlci0xMjM0NTY3OCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6InNlc3Npb24tMTIzNDU2NzgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoic2Vzc2lvbi0xMjM0NTY3OCIsInVzZXJfaWQiOiJ1c2VyMTIzIiwiY3VzdG9tZXJfaWRzIjpbIkNVU1QwMDEiLCJDVVNUMDAyIl0sImFjY2VwdGVkX3Rlcm1zIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJkaWdpdGFsX2lkIjoiZGlnLTEyMzQ1NiIsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20ifQ.SampleSignatureDataHereForTestingPurposesOnlyNotARealSignature123456789";
    
    // Base64 encoded JWT body only (without header and signature)
    const b64Body =
        "eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoidGVzdC11dWlkLTEyMzQtNTY3OC05YWJjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tL3JlYWxtcy90ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6InRlc3QtdXNlci0xMjM0NTY3OCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6InNlc3Npb24tMTIzNDU2NzgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoic2Vzc2lvbi0xMjM0NTY3OCIsInVzZXJfaWQiOiJ1c2VyMTIzIiwiY3VzdG9tZXJfaWRzIjpbIkNVU1QwMDEiLCJDVVNUMDAyIl0sImFjY2VwdGVkX3Rlcm1zIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJkaWdpdGFsX2lkIjoiZGlnLTEyMzQ1NiIsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20ifQ";
    
    // Malformed JWT token with corrupted data in header, body and signature
    const badJwtTokenString =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3RBAD1234Invalid!!@@##.eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoidGVzdC11dWlkLTEyMzQtNTY3OC05YWJjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tL3JlYWxtcy90ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6InRlc3QtdXNlci0xMjM0NTY3OCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6InNlc3Npb24tMTIzNDU2NzgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoic2Vzc2lvbi0xMjM0NTY3OCIsInVzZXJfaWQiOiJ1c2VyMTIzIiwiY3VzdG9tZXJfaWRzIjpbIkNVU1QwMDEiLCJDVVNUMDAyIl0sImFjY2VwdGVkX3Rlcm1zIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJkaWdpdGFsX2lkIjoiZGlnLTEyMzQ1NiIsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSIsImVtYWlsIjoiam9obi5kb2VAZXHBAD!!!Invalid.InvalidSignatureDataHere!!!@@@###$$%%^^&&**";
    
    // Malformed base64 body with invalid characters and truncated data
    const badJwtB64Body =
        "eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoidGVzdC11dWlkLTEyMzQtNTY3OC05YWJjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tL3JlYWxtcy90ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6InRlc3QtdXNlci0xMjM0NTY3OCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6InNlc3Npb24tMTIzNDU2NzgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoic2Vzc2lvbi0xMjM0NTY3OCIsInVzZXJfaWQiOiJ1c2VyMTIzIiwiY3VzdG9tZXJfaWRzIjpbIkNVU1QwMDEiLCJDVVNUMDAyIl0sImFjY2VwdGVkX3Rlcm1zIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJkaWdpdGFsX2lkIjoiZGlnLTEyMzQ1NiIsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSIsImVtYWlsIjoiam9obi5kb2VAINVALID!!!@@@";
    
    // JWT token with future expiration (2151) but not properly signed
    const jwtTokenExpire2151NotSigned =
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Rfa2V5XzEyMyJ9.eyJleHAiOjU3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoidGVzdC11dWlkLTEyMzQtNTY3OC05YWJjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUuY29tL3JlYWxtcy90ZXN0IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6InRlc3QtdXNlci0xMjM0NTY3OCIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6InNlc3Npb24tMTIzNDU2NzgiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoic2Vzc2lvbi0xMjM0NTY3OCIsInVzZXJfaWQiOiJ1c2VyMTIzIiwiY3VzdG9tZXJfaWRzIjpbIkNVU1QwMDEiLCJDVVNUMDAyIl0sImFjY2VwdGVkX3Rlcm1zIjoidHJ1ZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJkaWdpdGFsX2lkIjoiZGlnLTEyMzQ1NiIsIm5hbWUiOiJKb2huIERvZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJmYW1pbHlfbmFtZSI6IkRvZSIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20ifQ==.UnsignedTokenForTestingPurposesOnlyNotARealSignature123456789";

    describe("getDecodeXUserInfo", () => {
        it("should decode b64 body as a valid jwt token info", () => {
            const res = Base64Utils.getDecodeXUserInfo(b64Body);
            expect(res.email).toStrictEqual("john.doe@example.com");
        });

        it("should throw error because it is a full jwt token and not only the body part", () => {
            try {
                Base64Utils.getDecodeXUserInfo(jwtTokenString);
                expect(true).toBe(false);
            } catch (error) {
                expect((error as HttpException).message).toStrictEqual(
                    ErrorEnum.INVALID_TOKEN
                );
            }
        });

        it("should throw error because it a bad jwt token b64 body", () => {
            try {
                Base64Utils.getDecodeXUserInfo(badJwtB64Body);
                expect(true).toBe(false);
            } catch (error) {
                expect((error as HttpException).message).toStrictEqual(
                    ErrorEnum.INVALID_TOKEN
                );
            }
        });
    });

    describe("isTokenExpired", () => {
        it("should be not expired", () => {
            // This token expires in 2151 but it's not signed
            // This function does not check the signature validity
            expect(
                Base64Utils.isTokenExpired(jwtTokenExpire2151NotSigned)
            ).toBe(false);
        });

        it("should be expired", () => {
            expect(Base64Utils.isTokenExpired(jwtTokenString)).toBe(true);
        });

        it("should throw error", () => {
            try {
                Base64Utils.isTokenExpired(badJwtTokenString);
                expect(true).toBe(false);
            } catch (error) {
                expect((error as HttpException).message).toBe(
                    ErrorEnum.INVALID_TOKEN
                );
            }
        });
    });

    describe("getUserInfoFromAccessToken", () => {
        it("should decode bearer token as a valid jwt token info", () => {
            const res = Base64Utils.getUserInfoFromAccessToken(jwtTokenString);
            expect(res.email).toStrictEqual("john.doe@example.com");
        });

        it("should decode bearer token including bearer word as a valid jwt token info", () => {
            const res = Base64Utils.getUserInfoFromAccessToken(
                `bearer ${jwtTokenString}`
            );
            expect(res.email).toStrictEqual("john.doe@example.com");
        });

        it("should throw error", () => {
            try {
                Base64Utils.getUserInfoFromAccessToken(badJwtTokenString);
                expect(true).toBe(false);
            } catch (error) {
                expect((error as HttpException).message).toBe(
                    ErrorEnum.INVALID_TOKEN
                );
            }
        });

        it("should throw error because it's only b64 body", () => {
            try {
                Base64Utils.getUserInfoFromAccessToken(b64Body);
                expect(true).toBe(false);
            } catch (error) {
                expect((error as HttpException).message).toBe(
                    ErrorEnum.INVALID_TOKEN
                );
            }
        });
    });
});