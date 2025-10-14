import PaginationDto from "./pagination.dto";

export default class PaginatedWrapperDto<T> {
    items!: T[];
    pagination!: PaginationDto;
}
