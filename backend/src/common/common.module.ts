import { Module, NestModule, ValidationPipe } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { APP_FILTER, APP_INTERCEPTOR, APP_PIPE } from "@nestjs/core";
import ErrorExceptionFilter from "./filters/error-exception.filter";
import WrapResponseInterceptor from "./interceptors/wrap-response.interceptor";

@Module({
    imports: [ConfigModule],
    providers: [
        // apply this pipe for every incoming payload
        // this layer is mandatory to avoid unexpected inbound payload
        {
            provide: APP_PIPE,
            useFactory: () => {
                return new ValidationPipe({
                    whitelist: true,
                    transform: true, // change the payload into an actual object
                    transformOptions: {
                        enableImplicitConversion: true // instead of declaring @Type
                    }
                });
            }
        },
        // apply this filter for every execution, no need to trycatch anymore
        // this layer is mandatory to avoid unexpected server shutdown
        {
            provide: APP_FILTER,
            useClass: ErrorExceptionFilter
        },
        // apply this interceptor for every call, wrap response payload
        // this interceptor is optional, comment it if a wrap layer is not needed
        {
            provide: APP_INTERCEPTOR,
            useClass: WrapResponseInterceptor
        }

        // user guard
        // {
        //     provide: APP_GUARD,
        //     useClass: UserGuard
        // }
    ]
})
export default class CommonModule implements NestModule {
    configure(): void {}
}
