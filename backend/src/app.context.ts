import {
    INestApplication,
    InternalServerErrorException,
    Type
} from "@nestjs/common";

/**
 * This class contains the static reference in memory of INestApplication
 */
export default class AppContext {
    private static app: INestApplication;

    /**
     * Return true if AppContext is registered
     * @returns boolean
     */
    static isContext(): boolean {
        return typeof AppContext.app !== "undefined";
    }

    /**
     * Register pointer of INestApplication
     * Must be call only in main.ts, once
     *
     * @param app
     */
    static setContext(app: INestApplication): void {
        if (AppContext.isContext()) {
            throw new InternalServerErrorException(
                "AppContext is already registered"
            );
        }

        AppContext.app = app;
    }

    /**
     * Given a type or a token it retrives the instance in memory
     *
     * Usage example: `const INSTANCE = AppContext.get(MyService);`
     * where MyService is an `@Injectable` nest class, initializated inside the nest application via module syntax
     * </pre>
     *
     * @param typeOrToken
     * @returns
     */
    static get<TInput = unknown, TResult = TInput>(
        typeOrToken: Type<TInput> | Function | string | symbol
    ): TResult {
        return AppContext.app.get(typeOrToken);
    }
}
