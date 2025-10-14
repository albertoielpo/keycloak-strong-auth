import { Type, applyDecorators } from "@nestjs/common";
import { ApiOkResponse, getSchemaPath } from "@nestjs/swagger";

const OkResponse = <TModel extends Type<unknown>>(model: TModel) => {
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
                                    $ref: getSchemaPath(model)
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

export default OkResponse;
