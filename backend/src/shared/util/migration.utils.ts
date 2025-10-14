import { Logger } from "@nestjs/common";
import { config, database, down, up } from "migrate-mongo";
// eslint-disable-next-line import/no-extraneous-dependencies
import * as mongo from "mongodb";

export interface IMongoMigrateConf {
    mongodb: {
        url: string;
    };
    migrationsDir: string;
    changelogCollectionName: string;
    migrationFileExtension: string;
}

export default class MigrationUtils {
    private readonly logger: Logger;
    private readonly conf: IMongoMigrateConf;
    private readonly connection: typeof database;
    private readonly startMigrate: typeof up;
    private readonly startRollback: typeof down;
    private readonly migrateMongoConfiguration: typeof config;
    private readonly ttl = 1000 * 60 * 10; // 10 minutes

    constructor(
        dbUrl: string,
        logger: Logger,
        migrateMongoDatabaseConnection: typeof database,
        migrateMongoStartMigrate: typeof up,
        migrateMongoStartRollback: typeof down,
        migrateMongoConfiguration: typeof config
    ) {
        this.logger = logger;
        this.conf = {
            mongodb: {
                url: dbUrl
            },
            migrationsDir: "resources/migrations",
            changelogCollectionName: "changelog",
            migrationFileExtension: ".js"
        };
        this.connection = migrateMongoDatabaseConnection;
        this.startMigrate = migrateMongoStartMigrate;
        this.startRollback = migrateMongoStartRollback;
        this.migrateMongoConfiguration = migrateMongoConfiguration;

        this.migrateMongoConfiguration.set(this.conf);
        logger.log("MigrationUtils initialized");
    }

    public async migrateUp(): Promise<void> {
        this.logger.debug("migrate up");
        const functionToExecute = async (
            db: mongo.Db & { close: mongo.MongoClient["close"] },
            client: mongo.MongoClient
        ): Promise<void> => {
            this.logger.log("Migrating...");
            const migrated = await this.startMigrate(db, client);
            if (migrated.length === 0) {
                this.logger.log("No migrations to process");
            }

            for (const fileName of migrated) {
                this.logger.log(`Migration processed: ${fileName}`);
            }
        };
        return this.migrate(functionToExecute);
    }

    public async migrateDown(): Promise<void> {
        this.logger.debug("migrate down");
        const functionToExecute = async (
            db: mongo.Db & { close: mongo.MongoClient["close"] },
            client: mongo.MongoClient
        ): Promise<void> => {
            this.logger.log("Performing rollback");
            try {
                const rollbackMigrations = await this.startRollback(db, client);
                for (const fileName of rollbackMigrations) {
                    this.logger.log(
                        `Rollback migration processed: ${fileName}`
                    );
                }
            } catch (e) {
                this.logger.log("Rollback failed:", e);
            }
        };
        return this.migrate(functionToExecute);
    }

    public async migrate(
        functionToExecute: (
            db: mongo.Db & { close: mongo.MongoClient["close"] },
            client: mongo.MongoClient
        ) => Promise<void>
    ): Promise<void> {
        const { db, client, hasLock } = await this.getLock();
        if (!hasLock) {
            this.logger.log("Lock found, skipping");
            return;
        }
        await functionToExecute(db, client);

        this.logger.log("Dropping lock entry");
        await db
            .collection("migration-lock")
            .deleteOne({ lockTimestamp: { $exists: true } });
        this.logger.log("Migration completed");
    }

    private async getLock(): Promise<{
        db: mongo.Db & {
            close: mongo.MongoClient["close"];
        };
        client: mongo.MongoClient;
        hasLock: boolean;
    }> {
        this.logger.debug("get lock");

        const {
            db,
            client
        }: {
            client: mongo.MongoClient;
            db: mongo.Db & { close: mongo.MongoClient["close"] };
        } = await this.connection.connect();

        const entries = await db.collection("migration-lock").countDocuments();

        this.logger.debug(`entries: ${entries}`);
        if (entries > 1) {
            throw new Error(
                "Multiple locks found. migration-lock collection should have one entry"
            );
        }

        if (entries === 0) {
            // if does not exist then create with default timestamp. update with upsert true to avoid concurrency
            await db.collection("migration-lock").updateOne(
                {
                    lockTimestamp: {
                        $exists: true
                    }
                },
                {
                    $setOnInsert: {
                        lockTimestamp: new Date(0)
                    }
                },
                { upsert: true }
            );
        }

        let hasLock = false;
        this.logger.log("checking for lock...");
        // here the lock is always defined.. could be default, an expired one or a real lock.
        // the update is performed only if is possible to acquire the lock
        const data = await db.collection("migration-lock").updateOne(
            {
                lockTimestamp: {
                    $lte: new Date(new Date().valueOf() - this.ttl)
                }
            },
            {
                $set: {
                    lockTimestamp: new Date()
                }
            },
            { upsert: false }
        );
        // if the lock is acquired then modifiedCount is 1
        hasLock = Number(data.modifiedCount) === 1;
        this.logger.log(`migration-lock updated. hasLock: ${hasLock}`);
        return { db, client, hasLock };
    }
}

export function migrate(
    dbUrl: string,
    logger: Logger,
    migrateMongoObj: {
        databaseConnection: typeof database;
        startMigrate: typeof up;
        startRollback: typeof down;
        configuration: typeof config;
    },
    options: { isSwagger: boolean; isRollback: boolean }
): Promise<void> {
    logger.log(
        `Swagger option is ${options.isSwagger ? "enabled" : "disabled"}`
    );
    if (options.isSwagger) {
        return Promise.resolve();
    }
    const migrationUtils = new MigrationUtils(
        dbUrl,
        logger,
        migrateMongoObj.databaseConnection,
        migrateMongoObj.startMigrate,
        migrateMongoObj.startRollback,
        migrateMongoObj.configuration
    );
    if (options.isRollback) {
        return migrationUtils.migrateDown();
    }
    return migrationUtils.migrateUp();
}
