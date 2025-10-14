import {
    ArgumentsHost,
    Catch,
    ExceptionFilter,
    HttpException,
    Logger
} from "@nestjs/common";

import { FastifyReplyWrap } from "../../shared/type/backend.type";
import ErrorMessageDto from "../dto/error-message.dto";
import { ErrorEnum } from "../enum/error.enum";
import ErrorExceptionUtil from "./error-exception.util";

@Catch(Error)
export default class ErrorExceptionFilter<T extends HttpException | Error>
    implements ExceptionFilter
{
    private readonly logger = new Logger(ErrorExceptionFilter.name);

    private static isDebugEnabled(): boolean {
        return process.env.APP_ENV !== "prod";
    }

    catch(exception: T, host: ArgumentsHost): FastifyReplyWrap {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse(); // express or fastify
        const status = ErrorExceptionUtil.buildStatus(exception);
        return response
            .status(status)
            .send(this.buildErrorMessageDto(exception, status));
    }

    /**
     * Build the "message" used as code
     * @param exception
     * @returns
     */
    private static buildMessage(
        exception: HttpException | Error
    ): string | "suppress_log" {
        if (ErrorExceptionUtil.isHttpException(exception)) {
            // Http managed exception
            const httpException = exception.getResponse();
            if (typeof httpException === "object") {
                // message is the code
                return (<{ message: string }>httpException).message;
            }
            // inline code
            return httpException;
        }

        // unexpected error - message is the code
        return exception.message;
    }

    private buildErrorMessageDto(
        exception: HttpException | Error,
        statusCode: number
    ): ErrorMessageDto {
        const status =
            statusCode >= 400 && statusCode <= 499 ? "FAIL" : "ERROR";

        let message: string | "suppress_log" =
            ErrorExceptionFilter.buildMessage(exception);

        if (message === "suppress_log") {
            // in case of suppress_log then return directly without logging
            return ErrorExceptionFilter.isDebugEnabled()
                ? { status, message, debug: exception }
                : { status, message };
        }

        if (!ErrorEnum[message as keyof typeof ErrorEnum]) {
            // here when the message is not a managed key
            if (status === "FAIL") {
                if (statusCode === 401 || statusCode === 403) {
                    // default as invalid token in case of 401 / 403
                    message = ErrorEnum.INVALID_TOKEN;
                } else {
                    message = ErrorEnum.INVALID_PARAMETERS;
                }
            } else {
                message = ErrorEnum.GENERIC_SERVER_ERROR;
            }
        }

        if (status === "FAIL") {
            this.logger.warn(exception, "message");
        } else {
            this.logger.error(exception, "message");
        }

        return ErrorExceptionFilter.isDebugEnabled()
            ? { status, message, debug: exception }
            : { status, message };
    }
}
