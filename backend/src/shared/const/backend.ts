// fetch signal: AbortSignal.timeout(ABORT_TIMEOUT)
export const ABORT_TIMEOUT: number = 30_000; // ms

// exception names
export const CONNECTION_REFUSED_NAME = "ECONNREFUSED";
export const TIMEOUT_EXCEPTION_NAME = "TimeoutError";
export const FETCH_EXCEPTION_NAME = "TypeError";

export const REDLOCK_QUOTE_REACHED_ERROR = {
    name: "ExecutionError",
    message:
        "The operation was unable to achieve a quorum during its retry window."
};

// 16 bytes
export const DEFAULT_CIPHER_KEY = "5897521444102584";
