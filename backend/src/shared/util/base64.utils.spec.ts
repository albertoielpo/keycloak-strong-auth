import { HttpException } from "@nestjs/common";
import { ErrorEnum } from "../../common/enum/error.enum";
import Base64Utils from "./base64.utils";

describe("Base64Utils", () => {
    const jwtTokenString =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtclk0dGIxemdBM0RWOGtGcklkZzh4RjNyVHo1dldqYTFhanc2SHN5T2g0In0.eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoiZDlhOWVjNGQtYzAxYS00N2Y1LWE0M2UtMzhhN2JlZTMxNjZjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZlZ2FjYXJidXJhbnRpLml0L2F1dGgvcmVhbG1zL1ZFR0FTVEFHSU5HIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImJjYTMwZmJmLTJiNGItNDQ2OC1hMmIwLTIyYmVkNTM1OWY2NyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVubm92YSIsInNlc3Npb25fc3RhdGUiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdmVnYXN0YWdpbmciLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgdmVnYS1hdHRyaWJ1dGVzIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJzYXBfY3VzdG9tZXJzIjpbIjIwMDAwMDAxMTYiXSwic2FwX2NhcmRzIjp7IjEwMDAwMDAwMDEiOlsiODkwMTg4ODg5NiIsIjg5MDEwMDgyNDMiLCIxNTEwMDAwODk3Il19LCJhY2NlcHRlZF9wcml2YWN5X3BvbGljeSI6IjIwMjQtMDMtMjUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWNjZXB0ZWRfdGVybXNfY29uZGl0aW9ucyI6IjIwMjQtMDMtMjUiLCJkaWdpdGFsX3BsYXRmb3JtX2lkIjoiNjVlNzQwZWMwMjBmYjI2N2JkNWQ0ODhkIiwibmFtZSI6ImFsYmVydG8gaWVscG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20iLCJtYXJrZXRpbmdfYWxsb3dlZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6ImFsYmVydG8iLCJmYW1pbHlfbmFtZSI6ImllbHBvIiwiZW1haWwiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20ifQ.NcfDlkYAMtHFAo9SANLVo7it-DJuZX9zj_CseiqcUOkuL9Jcy1GyQ-bqG8hHb8LsTGKcq6qqYgag_ArK1Q18kOfMV3tKoJk2Q4oAK6opZBeypHamT91vpu97qOZ51FzrdN10-K0latuKhOLerl8Q6DjMG20k3vdVbnrJu5KgURsYxogxp8ApDGrHigKjcNUqigMVsO3ENyHSK6fDAWPxInLZtv1beKZI8FiCGv5J-JQ2hf-g4GFKO1DR2zUeMpLErdKaMC5FIP762nX00B7WpOQsVBx8MusYxt4hucdejL94yj-ez5ueHZRoJDMuF_Qe8lu5L-homgLLjx7Mrqnc2w";
    const b64Body =
        "eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoiZDlhOWVjNGQtYzAxYS00N2Y1LWE0M2UtMzhhN2JlZTMxNjZjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZlZ2FjYXJidXJhbnRpLml0L2F1dGgvcmVhbG1zL1ZFR0FTVEFHSU5HIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImJjYTMwZmJmLTJiNGItNDQ2OC1hMmIwLTIyYmVkNTM1OWY2NyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVubm92YSIsInNlc3Npb25fc3RhdGUiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdmVnYXN0YWdpbmciLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgdmVnYS1hdHRyaWJ1dGVzIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJzYXBfY3VzdG9tZXJzIjpbIjIwMDAwMDAxMTYiXSwic2FwX2NhcmRzIjp7IjEwMDAwMDAwMDEiOlsiODkwMTg4ODg5NiIsIjg5MDEwMDgyNDMiLCIxNTEwMDAwODk3Il19LCJhY2NlcHRlZF9wcml2YWN5X3BvbGljeSI6IjIwMjQtMDMtMjUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWNjZXB0ZWRfdGVybXNfY29uZGl0aW9ucyI6IjIwMjQtMDMtMjUiLCJkaWdpdGFsX3BsYXRmb3JtX2lkIjoiNjVlNzQwZWMwMjBmYjI2N2JkNWQ0ODhkIiwibmFtZSI6ImFsYmVydG8gaWVscG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20iLCJtYXJrZXRpbmdfYWxsb3dlZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6ImFsYmVydG8iLCJmYW1pbHlfbmFtZSI6ImllbHBvIiwiZW1haWwiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20ifQ";
    const badJwtTokenString =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtclk0dGIxemdBM0RWOGtGcklkZzh4RjNyVHo1dldqYTFhanc21234567890.eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoiZDlhOWVjNGQtYzAxYS00N2Y1LWE0M2UtMzhhN2JlZTMxNjZjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZlZ2FjYXJidXJhbnRpLml0L2F1dGgvcmVhbG1zL1ZFR0FTVEFHSU5HIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImJjYTMwZmJmLTJiNGItNDQ2OC1hMmIwLTIyYmVkNTM1OWY2NyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVubm92YSIsInNlc3Npb25fc3RhdGUiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdmVnYXN0YWdpbmciLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgdmVnYS1hdHRyaWJ1dGVzIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJzYXBfY3VzdG9tZXJzIjpbIjIwMDAwMDAxMTYiXSwic2FwX2NhcmRzIjp7IjEwMDAwMDAwMDEiOlsiODkwMTg4ODg5NiIsIjg5MDEwMDgyNDMiLCIxNTEwMDAwODk3Il19LCJhY2NlcHRlZF9wcml2YWN5X3BvbGljeSI6IjIwMjQtMDMtMjUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWNjZXB0ZWRfdGVybXNfY29uZGl0aW9ucyI6IjIwMjQtMDMtMjUiLCJkaWdpdGFsX3BsYXRmb3JtX2lkIjoiNjVlNzQwZWMwMjBmYjI2N2JkNWQ0ODhkIiwibmFtZSI6ImFsYmVydG8gaWVscG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20iLCJtYXJrZXRpbmdfYWxsb3dlZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6ImFsYmVydG8iLCJmYW1pbHlfbmFtZSI6ImllbHBvIiwiZW1haWwiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJj1234567890.NcfDlkYAMtHFAo9SANLVo7it-DJuZX9zj_CseiqcUOkuL9Jcy1GyQ-bqG8hHb8LsTGKcq6qqYgag_ArK1Q18kOfMV3tKoJk2Q4oAK6opZBeypHamT91vpu97qOZ51FzrdN10-K0latuKhOLerl8Q6DjMG20k3vdVbnrJu5KgURsYxogxp8ApDGrHigKjcNUqigMVsO3ENyHSK6fDAWPxInLZtv1beKZI8FiCGv5J-JQ2hf-g4GFKO1DR2zUeMpLErdKaMC5FIP762nX00B7WpOQsVBx8MusYxt4hucdejL94yj-ez5ueHZRoJDMuF_Qe8lu5L-homgLL1234567890";
    const badJwtB64Body =
        "eyJleHAiOjE3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoiZDlhOWVjNGQtYzAxYS00N2Y1LWE0M2UtMzhhN2JlZTMxNjZjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZlZ2FjYXJidXJhbnRpLml0L2F1dGgvcmVhbG1zL1ZFR0FTVEFHSU5HIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImJjYTMwZmJmLTJiNGItNDQ2OC1hMmIwLTIyYmVkNTM1OWY2NyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVubm92YSIsInNlc3Npb25fc3RhdGUiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdmVnYXN0YWdpbmciLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgdmVnYS1hdHRyaWJ1dGVzIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJzYXBfY3VzdG9tZXJzIjpbIjIwMDAwMDAxMTYiXSwic2FwX2NhcmRzIjp7IjEwMDAwMDAwMDEiOlsiODkwMTg4ODg5NiIsIjg5MDEwMDgyNDMiLCIxNTEwMDAwODk3Il19LCJhY2NlcHRlZF9wcml2YWN5X3BvbGljeSI6IjIwMjQtMDMtMjUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWNjZXB0ZWRfdGVybXNfY29uZGl0aW9ucyI6IjIwMjQtMDMtMjUiLCJkaWdpdGFsX3BsYXRmb3JtX2lkIjoiNjVlNzQwZWMwMjBmYjI2N2JkNWQ0ODhkIiwibmFtZSI6ImFsYmVydG8gaWVscG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20iLCJtYXJrZXRpbmdfYWxsb3dlZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6ImFsYmVydG8iLCJmYW1pbHlfbmFtZSI6ImllbHBvIiwiZW1haWwiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJj1234567890";
    const jwtTokenExpire2151NotSigned =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtclk0dGIxemdBM0RWOGtGcklkZzh4RjNyVHo1dldqYTFhanc2SHN5T2g0In0.eyJleHAiOjU3MTU2NzQ3MjQsImlhdCI6MTcxNTY3NDEyNCwianRpIjoiZDlhOWVjNGQtYzAxYS00N2Y1LWE0M2UtMzhhN2JlZTMxNjZjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLnZlZ2FjYXJidXJhbnRpLml0L2F1dGgvcmVhbG1zL1ZFR0FTVEFHSU5HIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImJjYTMwZmJmLTJiNGItNDQ2OC1hMmIwLTIyYmVkNTM1OWY2NyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImVubm92YSIsInNlc3Npb25fc3RhdGUiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdmVnYXN0YWdpbmciLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgdmVnYS1hdHRyaWJ1dGVzIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiJhOWQ4NGViMi1lZWMxLTRkZWQtYjk4MC0xMTY5ZTAyNWQwNGUiLCJzYXBfY3VzdG9tZXJzIjpbIjIwMDAwMDAxMTYiXSwic2FwX2NhcmRzIjp7IjEwMDAwMDAwMDEiOlsiODkwMTg4ODg5NiIsIjg5MDEwMDgyNDMiLCIxNTEwMDAwODk3Il19LCJhY2NlcHRlZF9wcml2YWN5X3BvbGljeSI6IjIwMjQtMDMtMjUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYWNjZXB0ZWRfdGVybXNfY29uZGl0aW9ucyI6IjIwMjQtMDMtMjUiLCJkaWdpdGFsX3BsYXRmb3JtX2lkIjoiNjVlNzQwZWMwMjBmYjI2N2JkNWQ0ODhkIiwibmFtZSI6ImFsYmVydG8gaWVscG8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20iLCJtYXJrZXRpbmdfYWxsb3dlZCI6dHJ1ZSwiZ2l2ZW5fbmFtZSI6ImFsYmVydG8iLCJmYW1pbHlfbmFtZSI6ImllbHBvIiwiZW1haWwiOiJhbGJlcnRvLmllbHBvQGVubm92YS1yZXNlYXJjaC5jb20ifQ==.NcfDlkYAMtHFAo9SANLVo7it-DJuZX9zj_CseiqcUOkuL9Jcy1GyQ-bqG8hHb8LsTGKcq6qqYgag_ArK1Q18kOfMV3tKoJk2Q4oAK6opZBeypHamT91vpu97qOZ51FzrdN10-K0latuKhOLerl8Q6DjMG20k3vdVbnrJu5KgURsYxogxp8ApDGrHigKjcNUqigMVsO3ENyHSK6fDAWPxInLZtv1beKZI8FiCGv5J-JQ2hf-g4GFKO1DR2zUeMpLErdKaMC5FIP762nX00B7WpOQsVBx8MusYxt4hucdejL94yj-ez5ueHZRoJDMuF_Qe8lu5L-homgLLjx7Mrqnc2w";

    describe("getDecodeXUserInfo", () => {
        it("should decore b64 body as a valid jwt token info", () => {
            const res = Base64Utils.getDecodeXUserInfo(b64Body);
            expect(res.email).toStrictEqual(
                "alberto.ielpo@ennova-research.com"
            );
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
            // this token expires in 2037 but it's not signed
            // this function does not check the signature validity
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
            expect(res.email).toStrictEqual(
                "alberto.ielpo@ennova-research.com"
            );
        });

        it("should decode bearer token including bearer word as a valid jwt token info", () => {
            const res = Base64Utils.getUserInfoFromAccessToken(
                `bearer ${jwtTokenString}`
            );
            expect(res.email).toStrictEqual(
                "alberto.ielpo@ennova-research.com"
            );
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
