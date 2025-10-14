import { Type, applyDecorators } from "@nestjs/common";
import { ApiOkResponse, getSchemaPath } from "@nestjs/swagger";

const OkResponseSse = <TModel extends Type<unknown>>(
    model: TModel,
    type: string[]
) => {
    return (
        target: object | Function,
        methodName: string,
        descriptor: PropertyDescriptor
    ) => {
        return applyDecorators(
            ApiOkResponse({
                schema: {
                    description: "sseNotifications",
                    properties: {
                        data: {
                            $ref: getSchemaPath(model)
                        },
                        id: {
                            type: "string"
                        },
                        type: {
                            type: "string",
                            enum: type
                        },
                        retry: {
                            type: "number"
                        }
                    },
                    required: ["data", "id", "type"]
                }
            })
        )(target, methodName, descriptor);
    };
};

export default OkResponseSse;
