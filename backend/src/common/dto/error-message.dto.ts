export default class ErrorMessageDto {
    status!: "FAIL" | "ERROR";
    message?: string;
    debug?: unknown;
}
