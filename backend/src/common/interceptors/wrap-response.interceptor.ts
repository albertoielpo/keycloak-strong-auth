import {
    CallHandler,
    ExecutionContext,
    Injectable,
    NestInterceptor
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
// eslint-disable-next-line import/no-extraneous-dependencies
import { FastifyReply } from "fastify";
import { Observable, map } from "rxjs";
import {
    RESPONSE_WRAP_KEY,
    ResponseWrapOptions
} from "../decorators/response-wrap.decorator";
import OkMessageDto from "../dto/ok.message.dto";

@Injectable()
export default class WrapResponseInterceptor implements NestInterceptor {
    constructor(private readonly reflector: Reflector) {}

    private static getResponse(context: ExecutionContext): FastifyReply {
        const ctx = context.switchToHttp();
        return ctx.getResponse<FastifyReply>();
    }

    intercept(
        context: ExecutionContext,
        next: CallHandler
    ): Observable<OkMessageDto> {
        return next.handle().pipe(
            map((data) => {
                /**
                 * after response execution...
                 * if an exception is thrown this code is not executed
                 */
                const options: ResponseWrapOptions | undefined =
                    this.reflector.get(RESPONSE_WRAP_KEY, context.getHandler());
                const response = WrapResponseInterceptor.getResponse(context);

                // set return content-type
                // eslint-disable-next-line @typescript-eslint/no-floating-promises
                response.header(
                    "content-type",
                    options?.contentType ?? "application/json"
                );

                switch (options?.type) {
                    case "plain":
                        return data;
                    case "default":
                    default:
                        return {
                            status: "OK",
                            data
                        } as OkMessageDto;
                }
            })
        );
    }
}
