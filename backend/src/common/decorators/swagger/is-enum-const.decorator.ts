import { applyDecorators } from "@nestjs/common";
import { ApiProperty } from "@nestjs/swagger";

const IsEnumConst = <TEnumConstArray extends readonly string[]>(
    enumConstArray: TEnumConstArray,
    isArrayInDto?: boolean
) => {
    return applyDecorators(
        ApiProperty({ enum: enumConstArray, isArray: isArrayInDto })
    );
};
export default IsEnumConst;
