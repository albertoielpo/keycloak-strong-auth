import { INestApplication, InternalServerErrorException } from "@nestjs/common";
import AppContext from "./app.context";

describe("AppContext", () => {
    beforeAll(() => {
        const mockNestApplication = {
            listen: jest.fn().mockResolvedValue(undefined),
            close: jest.fn().mockResolvedValue(undefined),
            get: jest.fn().mockImplementation((token) => {
                // always return generic func
                if (token === "test-token") return jest.fn();
                throw new Error("token not found");
            }),
            use: jest.fn(),
            init: jest.fn().mockResolvedValue(undefined),
            enableCors: jest.fn()
        } as unknown as INestApplication;
        AppContext.setContext(mockNestApplication);
    });

    it("should be initialized", () => {
        expect(AppContext.isContext()).toBe(true);
    });

    it("should not possibile to init multiple times", () => {
        const mockNestApplication = {
            listen: jest.fn().mockResolvedValue(undefined),
            close: jest.fn().mockResolvedValue(undefined),
            get: jest.fn().mockImplementation((token) => {
                // always return generic func
                return jest.fn();
            }),
            use: jest.fn(),
            init: jest.fn().mockResolvedValue(undefined),
            enableCors: jest.fn()
        } as unknown as INestApplication;
        try {
            AppContext.setContext(mockNestApplication);
            expect(true).toBe(false);
        } catch (err) {
            expect(err).toBeInstanceOf(InternalServerErrorException);
        }
    });

    it("should retrieve an instance", () => {
        expect(AppContext.get("test-token")).toBeDefined();
    });

    it("should not retrieve an instance", () => {
        try {
            AppContext.get("bad-token");
            expect(true).toBe(false);
        } catch (error) {
            expect(error).toBeInstanceOf(Error);
        }
    });
});
