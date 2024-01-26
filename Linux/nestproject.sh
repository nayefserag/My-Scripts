#!/bin/bash

# Prompt the user for the project name
read -p "Enter your NestJS project name: " projectName

# Install NestJS globally (if not already installed)
npm install -g @nestjs/cli

# Create a new NestJS app
nest new "$projectName" --package-manager npm

# Navigate into the project directory
cd "$projectName/src"

# Create directories
mkdir -p components config helpers logging options repos Schema

# Write content to idValidator.ts in helpers directory
cat <<EOF >helpers/idValidator.ts
import { Types, isValidObjectId } from 'mongoose';

export function isValidObjectID(id: string): boolean {
  return isValidObjectId(id);
}

export function constructObjId(id: string | Types.ObjectId) {
  return new Types.ObjectId(id);
}
EOF

# Write content to numberGenerator.ts in helpers directory
cat <<EOF >helpers/numberGenerator.ts
import { v4 as uuidv4 } from 'uuid';

export function generator(type: string): string {
  const uuid = uuidv4().replace(/-/g, '');
  const numericOnly = uuid.replace(/\D/g, ''); // Remove non-numeric characters
  const shuffle = numericOnly
    .split('')
    .sort(function () {
      return 0.5 - Math.random();
    })
    .join('');

  if (type === 'Account Number') {
    return shuffle.substring(0, 16);
  }

  return shuffle;
}
EOF

# Write content to password.ts in helpers directory
cat <<EOF >helpers/password.ts
import * as bcrypt from 'bcrypt';

export class Password {
  public static async hashPassword(plainTextPassword: string): Promise<string> {
    const salt = await bcrypt.genSalt(process.env.SALT_ROUNDS);
    const hashedPassword = await bcrypt.hash(plainTextPassword, salt);
    return hashedPassword;
  }

  public static async Match(
    hashedPassword: string,
    plainTextPassword: string,
  ): Promise<boolean> {
    const isMatch = await bcrypt.compare(hashedPassword, plainTextPassword);
    return isMatch;
  }
}
EOF

# Write content to http-exception.filter.ts in logging directory
cat <<EOF >logging/http-exception.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import * as winston from 'winston';
import * as path from 'path';
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger: winston.Logger;

  constructor() {
    const logFilePath = path.join('logs', 'error.log');
    this.logger = winston.createLogger({
      level: 'error',
      format: winston.format.json(),
      transports: [new winston.transports.File({ filename: logFilePath })],
    });
  }

  catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const logMessage = {
      message: exception.message,
      statusCode: status,
      method: request.method,
      path: request.url,
      timestamp: new Date().toISOString(),
    };

    this.logger.error(logMessage);

    response.status(status).json(logMessage);
  }
}
EOF

# Write content to logging.interceptor.ts in logging directory
cat <<EOF >logging/logging.interceptor.ts
import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import * as path from 'path';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import * as winston from 'winston';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger: winston.Logger;

  constructor() {
    const logFilePath = path.join('logs', 'requests.log');
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [new winston.transports.File({ filename: logFilePath })],
    });
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const beforeReqTime = Date.now();
    const method = context.switchToHttp().getRequest().method;
    const url = context.switchToHttp().getRequest().url;

    return next.handle().pipe(
      tap(() => {
        const afterReqTime = Date.now();
        const logMessage = {
          method,
          url,
          responseTime: `${afterReqTime - beforeReqTime}ms`,
          timestamp: new Date().toISOString(),
        };

        this.logger.info(logMessage);
      }),
    );
  }
}
EOF

# Write content to swagger.config.ts in config directory
cat <<EOF >config/swagger.config.ts
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { INestApplication } from '@nestjs/common';
export function setupSwagger(app: INestApplication) {
  const options = new DocumentBuilder()
    .setTitle('App')
    .setDescription('Default')
    .setVersion('1.0')
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('docs', app, document);
}
EOF

# Write content to main.ts in src directory
cat <<EOF >main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { setupSwagger } from './config/swagger.config';
import { HttpExceptionFilter } from './logging/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
  app.useGlobalFilters(new HttpExceptionFilter());
  setupSwagger(app);
  await app.listen(3000);
}
bootstrap();
EOF

# Write content to tsconfig.json
cat <<EOF >tsconfig.json
{
  "compilerOptions": {
    "module": "commonjs",
    "declaration": true,
    "removeComments": true,
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "allowSyntheticDefaultImports": true,
    "target": "ES2021",
    "sourceMap": true,
    "outDir": "./dist",
    "baseUrl": "./",
    "incremental": true,
    "skipLibCheck": true,
    "strictNullChecks": true,
    "strict": true,
    "noImplicitAny": false,
    "strictBindCallApply": false,
    "forceConsistentCasingInFileNames": true,
    "noFallthroughCasesInSwitch": false
  }
}
EOF

# Create .env file
touch .env

# Install dependencies
npm i winston bcrypt uuid mongoose @nestjs/swagger class-validator class-transformer

# Start the application
npm run start
