import { Type, applyDecorators } from "@nestjs/common";
import { ApiBody, getSchemaPath } from "@nestjs/swagger";

export default <TDataModel extends Type<unknown>>(
    dataModels: Record<string, TDataModel>,
    discriminatorPropertyName: string
) => {
    const oneOfs: Record<"$ref", string>[] = [];
    const discriminatorMapping: Record<string, string> = {};

    for (const templateName in dataModels) {
        oneOfs.push({
            $ref: getSchemaPath(dataModels[templateName])
        });
        discriminatorMapping[templateName] = getSchemaPath(
            dataModels[templateName]
        );
    }

    return applyDecorators(
        ApiBody({
            schema: {
                oneOf: [...oneOfs],
                discriminator: {
                    propertyName: discriminatorPropertyName,
                    mapping: discriminatorMapping
                }
            }
        })
    );
};
