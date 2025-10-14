import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { LoggerModule } from "nestjs-pino";
import CommonModule from "./common/common.module";
import UsersModule from "./users/users.module";

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: false, // true === import automatically in every nest module
            envFilePath: [
                `${process.cwd()}/env/${process.env.APP_ENV || "local"}.env`, // first take precedence
                `${process.cwd()}/env/default.env` // it is used default only if the key is not found in the above file! If found with empty value, then is used empty
            ]
        }),
        LoggerModule.forRoot({
            pinoHttp: {
                level: process.env.LOG_LEVEL || "debug",
                redact: ["request.headers.authorization"],
                transport: {
                    targets: [
                        // log to standard output
                        {
                            target: "pino-pretty",
                            options: {
                                colorize: true,
                                singleLine: true,
                                levelFirst: false,
                                translateTime: "yyyy-mm-dd'T'HH:MM:ss.l'Z'",
                                // customize https://github.com/pinojs/pino-pretty
                                messageFormat:
                                    "[{req.headers.x-correlation-id}] [{context}] {msg}",
                                ignore: "pid,hostname,context,req,res,responseTime",
                                errorLikeObjectKeys: ["err", "error"]
                            },
                            level: process.env.LOG_LEVEL || "debug"
                        }
                    ]
                }
            }
        }),
        CommonModule,
        UsersModule
    ]
})
export default class AppModule {}
