import { SetMetadata } from "@nestjs/common";

export type ResponseWrapOptions = {
    // default generates OkResponseDto else not wrap is applied
    type?: "default" | "plain";
    contentType?:
        | "default"
        | "application/json"
        | "text/html"
        | "text/plain"
        | "application/pdf";
};

export const RESPONSE_WRAP_KEY = "responseWrap";
export const ResponseWrap = (options: ResponseWrapOptions) =>
    SetMetadata(RESPONSE_WRAP_KEY, options);
