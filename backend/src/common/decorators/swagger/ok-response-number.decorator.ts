import { applyDecorators } from "@nestjs/common";
import { ApiOkResponse } from "@nestjs/swagger";

const OkResponseNumber = () => {
    return (
        target: object | Function,
        methodName: string,
        descriptor: PropertyDescriptor
    ) => {
        return applyDecorators(
            ApiOkResponse({
                schema: {
                    description: methodName,
                    allOf: [
                        {
                            properties: {
                                status: {
                                    type: "string"
                                },
                                data: {
                                    type: "number"
                                }
                            },
                            required: ["status", "data"]
                        }
                    ]
                }
            })
        )(target, methodName, descriptor);
    };
};

export default OkResponseNumber;
