import { HttpException } from "@nestjs/common";

export default class ErrorExceptionUtil {
    public static isHttpException(
        exception: HttpException | Error
    ): exception is HttpException {
        return (
            typeof (<HttpException>exception).getStatus === "function" &&
            typeof (<HttpException>exception).getResponse === "function"
        );
    }

    public static buildStatus(exception: HttpException | Error): number {
        return ErrorExceptionUtil.isHttpException(exception)
            ? exception.getStatus()
            : 500;
    }
}
