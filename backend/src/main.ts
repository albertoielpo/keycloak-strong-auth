import { Logger as Log } from "@nestjs/common";
import { HttpsOptions } from "@nestjs/common/interfaces/external/https-options.interface";
import { NestFactory } from "@nestjs/core";
import {
    FastifyAdapter,
    NestFastifyApplication
} from "@nestjs/platform-fastify";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { Logger } from "nestjs-pino";
import { readFileSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import AppContext from "./app.context";
import AppModule from "./app.module";
import PaginationDto from "./common/dto/pagination.dto";

(async (): Promise<void> => {
    const logger = new Log("Main"); // explicit declare the @nestjs/common logger
    const port = Number.isNaN(Number(process.env.APP_PORT))
        ? 3000 // default port
        : Number(process.env.APP_PORT);
    const host = process.env.APP_HOST ?? "0.0.0.0"; // default is exposed in all network

    const isHttps = process.env.APP_HTTPS === "true"; // pass directly in docker compose

    let httpsOptions: undefined | HttpsOptions;
    if (isHttps) {
        // Load end user TLS server private key + certificate
        httpsOptions = {
            key: readFileSync(
                `${process.cwd()}/resources/certs/${process.env.APP_ENV || "local"}/server.key`
            ),
            cert: readFileSync(
                `${process.cwd()}/resources/certs/${process.env.APP_ENV || "local"}/server.crt`
            )
        };
    }
    const app = await NestFactory.create<NestFastifyApplication>(
        AppModule,
        new FastifyAdapter(httpsOptions ? { https: httpsOptions } : undefined),
        {
            bufferLogs: true,
            forceCloseConnections: true
        }
    );

    // cors configuration (no api gateway)
    app.enableCors({
        credentials: true,
        methods: [
            "GET",
            "HEAD",
            "PUT",
            "PATCH",
            "POST",
            "DELETE",
            "OPTIONS",
            "TRACE",
            "CONNECT"
        ],
        origin: "*",
        allowedHeaders: [
            "Accept",
            "Content-Length",
            "Content-Type",
            "Date",
            "If-None-Match",
            "Credentials",
            "Authorization"
        ],
        exposedHeaders: ["etag"],
        preflightContinue: false
    });

    app.enableShutdownHooks(); // onApplicationShutdown

    const options = new DocumentBuilder()
        .setTitle("microservice backend project")
        .setDescription("Swagger API documentation")
        .setVersion("1.0.0")
        .addCookieAuth("token")
        .build();

    const document = SwaggerModule.createDocument(app, options, {
        extraModels: [PaginationDto]
    });

    if (process.env.ONLY_SWAGGER_SPEC === "true") {
        /** generate and end node process */
        writeFileSync(
            `./generated/swagger-spec-${process.env.SDK_CLIENT}.json`,
            JSON.stringify(document)
        );
        console.log("swagger-spec generated");
        process.exit();
    }

    SwaggerModule.setup("api", app, document);

    // assign static context: use only in callback context where nestjs is not available
    AppContext.setContext(app);

    // assign to @nestjs/common, the async nestjs-pino logger
    app.useLogger(app.get(Logger));
    await app.listen({ port, host });
    logger.log(
        `NestApplication is running on ${host}:${port} in ${isHttps ? "https" : "http"}`
    );
    // print application version
    readFile(`${process.cwd()}/resources/version`, "utf8")
        .then((data) => {
            // file is docker build generated
            logger.log(`Version: ${data}`);
        })
        .catch(() => {
            logger.log(`Version: development mode`);
        });
})().catch((err) => console.log(err));
