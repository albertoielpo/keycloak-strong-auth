import {
    ArgumentMetadata,
    BadRequestException,
    Injectable,
    Logger,
    PipeTransform
} from "@nestjs/common";
import { isValidObjectId } from "mongoose";
import { ErrorEnum } from "../../enum/error.enum";

@Injectable()
export default class ParseMongoidPipe implements PipeTransform {
    private readonly logger = new Logger(ParseMongoidPipe.name);
    transform(value: unknown, metadata?: ArgumentMetadata): unknown {
        if (!isValidObjectId(value)) {
            this.logger.warn(
                `Validation failed. ${
                    metadata?.data ?? value
                } must be a mongodb id`
            );
            throw new BadRequestException(ErrorEnum.INVALID_ID);
        }
        return value;
    }
}
