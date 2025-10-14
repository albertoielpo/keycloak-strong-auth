import { firstValueFrom, of } from "rxjs";

import { ResponseWrapOptions } from "../decorators/response-wrap.decorator";
import OkMessageDto from "../dto/ok.message.dto";
import WrapResponseInterceptor from "./wrap-response.interceptor";

describe("WrapResponseInterceptor", () => {
    const buildMockInterceptor = (options: ResponseWrapOptions) => {
        /* data init ... */
        const mockReflector = {
            get: (a: unknown, b: unknown) => {
                return options;
            }
        } as any;
        return new WrapResponseInterceptor(mockReflector);
    };

    const executionContext = {
        getHandler: jest.fn().mockReturnValue({ fakeHandler: true }),

        switchToHttp: () => {
            return {
                getResponse: () => {
                    return {
                        // mock set headers
                        header: (a: string, b: string) => {
                            return {};
                        }
                    };
                }
            };
        }
    };

    const responsePayload = { randomProp: "randomValue" };
    const callHandler = {
        handle: () => of(responsePayload)
    };

    it("should be defined", () => {
        expect(
            buildMockInterceptor({
                type: "default",
                contentType: "application/json"
            })
        ).toBeDefined();
    });

    describe("#intercept", () => {
        it("should wrap the response object", async () => {
            const interceptor = buildMockInterceptor({
                type: "default",
                contentType: "application/json"
            });
            const obs = interceptor.intercept(
                executionContext as any, //ExecutionContext
                callHandler
            );

            //convert observable to promise.. unwrap value
            const res: OkMessageDto = (await firstValueFrom(
                obs
            )) as OkMessageDto;

            expect(res).toBeDefined();
            expect(res.status).toBe("OK");
            expect(res.data).toBe(responsePayload);
        });
    });

    describe("#intercept plain response without status-data wrap", () => {
        it("should wrap the response object", async () => {
            const interceptor = buildMockInterceptor({
                type: "plain",
                contentType: "application/json"
            });
            const obs = interceptor.intercept(
                executionContext as any, //ExecutionContext
                callHandler
            );

            //convert observable to promise.. unwrap value
            const res = await firstValueFrom(obs);

            expect(res).toBeDefined();
            expect((<any>res).randomProp).toBe("randomValue");
        });
    });
});
