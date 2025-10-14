export default class MongoUtils {
    // MongoDB ObjectId contains an embedded timestamp of its creation time
    public static objectIdFromDate(date: Date): string {
        return `${Math.floor(date.getTime() / 1000).toString(
            16
        )}0000000000000000`;
    }

    public static dateFromObjectId(objectId: string): Date {
        return new Date(parseInt(objectId.substring(0, 8), 16) * 1000);
    }

    /**
     * Check if is a mongo model using prototype constructor
     * @param model
     * @returns
     */
    public static isMongoModel(model: object | unknown): boolean {
        if (!model) {
            return false;
        }

        return (
            // HydratedDocument<T>
            (typeof model === "object" &&
                Object.getPrototypeOf(model.constructor).name === "Model") ||
            // Model<T>
            (typeof model === "function" &&
                Object.getPrototypeOf(model).name === "Model")
        );
    }
}
