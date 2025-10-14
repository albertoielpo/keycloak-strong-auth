import { Types } from "mongoose";
import ParseMongoidPipe from "./parse-mongoid.pipe";

import { BadRequestException } from "@nestjs/common";

describe("ParseMongoidPipe", () => {
    let pipe: ParseMongoidPipe = new ParseMongoidPipe();

    it("Verify the validity of a valid mongodb id", () => {
        const mongoid = new Types.ObjectId();
        const res = pipe.transform(mongoid);
        expect(res).toBe(mongoid);
    });

    it("BadRequestException if input is not valid mongodb id", () => {
        expect(() => pipe.transform("12345")).toThrow(BadRequestException);
        expect(() => pipe.transform("")).toThrow(BadRequestException);
        expect(() => pipe.transform(null)).toThrow(BadRequestException);
        expect(() => pipe.transform(undefined)).toThrow(BadRequestException);
        expect(() => pipe.transform([])).toThrow(BadRequestException);
        expect(() => pipe.transform({})).toThrow(BadRequestException);
    });
});
