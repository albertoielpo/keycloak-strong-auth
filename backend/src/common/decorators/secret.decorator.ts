import { SetMetadata } from "@nestjs/common";

export const IS_SECRET_KEY = "isSecret";
export const Secret = (header: string) => SetMetadata(IS_SECRET_KEY, header);
