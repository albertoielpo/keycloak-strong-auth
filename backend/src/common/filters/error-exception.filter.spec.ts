import { BadRequestException } from "@nestjs/common";
import ErrorMessageDto from "../dto/error-message.dto";

import { ErrorEnum } from "../enum/error.enum";
import ErrorExceptionFilter from "./error-exception.filter";

describe("ErrorExceptionFilter", () => {
    const filter = new ErrorExceptionFilter();
    const host = {
        switchToHttp: () => {
            return {
                getResponse: () => {
                    return {
                        status: (n: number) => {
                            return {
                                send: (errorDto: ErrorMessageDto) => {
                                    /*
                                     * This should return a FastifyReply
                                     * in this case is important to test the errorDto
                                     */
                                    return errorDto;
                                }
                            };
                        }
                    };
                }
            };
        }
    };

    it("Intercept bad request exception", () => {
        const ERROR_MESSAGE = ErrorEnum.INVALID_PARAMETERS;
        const res = filter.catch(
            new BadRequestException(ERROR_MESSAGE),
            host as any
        );

        /* res should be a FastifyReply */
        const errorDto: ErrorMessageDto = res as any;
        expect(errorDto).toBeDefined();
        expect(errorDto.status).toBe("FAIL");
        expect(errorDto.message).toBe(ERROR_MESSAGE);
    });

    it("Intercept generic error exception", () => {
        const ERROR_MESSAGE = ErrorEnum.GENERIC_SERVER_ERROR;
        const res = filter.catch(new Error(ERROR_MESSAGE), host as any);

        /* res should be a FastifyReply */
        const errorDto: ErrorMessageDto = res as any;
        expect(errorDto).toBeDefined();
        expect(errorDto.status).toBe("ERROR");
        expect(errorDto.message).toBe(ERROR_MESSAGE);
    });
});
