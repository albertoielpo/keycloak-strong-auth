import { applyDecorators } from "@nestjs/common";
import { ApiOkResponse } from "@nestjs/swagger";

const OkResponseVoid = () => {
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
                                }
                            },
                            required: ["status"]
                        }
                    ]
                }
            })
        )(target, methodName, descriptor);
    };
};

export default OkResponseVoid;
