import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, Logger, VersioningType } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import helmet from 'helmet';
import csrf from 'csurf';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';
import { winstonConfig } from './common/logger/logger.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: winstonConfig,
  });

  const configService = app.get(ConfigService);
  const logger = new Logger('Bootstrap');

  // Enable API versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
    prefix: 'api/v',
  });

  // Security: Helmet
  app.use(helmet());

  // Cookie parser (required for CSRF)
  app.use(cookieParser());

  // CSRF protection with conditional logic
  // Skip CSRF for Bearer token requests and public endpoints
  app.use((req, res, next) => {
    // Skip CSRF for Bearer token requests
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return next();
    }

    // Skip CSRF for public auth endpoints (OAuth flow, sign-in, sign-up)
    const publicEndpoints = [
      '/api/v1/auth/callback',
      '/api/v1/auth/signin-url',
      '/api/v1/auth/signup-url',
      '/api/v1/auth/refresh',
    ];

    if (publicEndpoints.some(endpoint => req.path.startsWith(endpoint))) {
      return next();
    }

    // Apply CSRF for cookie-based requests
    const csrfProtection = csrf({
      cookie: true,
      value: (req) => {
        // Extract CSRF token from header or body
        return req.headers['x-csrf-token'] || req.body?._csrf;
      },
    });

    csrfProtection(req, res, next);
  });

  // Session configuration
  app.use(
    session({
      secret: configService.get('SESSION_SECRET') || 'default-secret-change-in-production',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: configService.get('COOKIE_SECURE') === 'true',
        sameSite: configService.get('COOKIE_SAME_SITE') as any || 'lax',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    }),
  );

  // CORS configuration: allow all origins and domains
  app.enableCors({
    origin: true, // allow any origin (reflects request origin when credentials: true)
    credentials: true,
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-CSRF-Token',
      'Accept',
      'Origin',
    ],
  });

  // Global pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global filters
  app.useGlobalFilters(new AllExceptionsFilter());

  // Global interceptors
  app.useGlobalInterceptors(new LoggingInterceptor());

  // Swagger/OpenAPI configuration
  const config = new DocumentBuilder()
    .setTitle('N-Point SSO API')
    .setDescription(
      `NestJS backend with Casdoor SSO integration

**Base URL:** \`/api/v1\`

**Features:**
- OAuth 2.0 authentication with Casdoor
- JWT token-based authorization
- HTTP-only cookie support for enhanced security
- Role-based access control (RBAC)
- Permission-based authorization`,
    )
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
      },
      'JWT-auth',
    )
    .addCookieAuth(
      'access_token',
      {
        type: 'apiKey',
        in: 'cookie',
        name: 'access_token',
        description: 'JWT token stored in HTTP-only cookie',
      },
      'cookie-auth',
    )
    .addTag('auth', 'Authentication endpoints')
    .addTag('user', 'User profile and permissions endpoints')
    .addServer('http://localhost:3001', 'Development server')
    .addServer('http://localhost:3001/api/v1', 'API v1 (versioned)')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      tagsSorter: 'alpha',
      operationsSorter: 'alpha',
    },
    customSiteTitle: 'N-Point SSO API Documentation',
  });

  const port = configService.get('PORT') || 3001;
  const nodeEnv = configService.get('NODE_ENV') || 'development';

  await app.listen(port);

  logger.log(`🚀 Application is running in ${nodeEnv} mode`);
  logger.log(`🔗 Backend server: http://localhost:${port}`);
  logger.log(`📚 API documentation: http://localhost:${port}/api/docs`);
  logger.log(`🔢 API version: v1 (base path: /api/v1)`);
  logger.log(`🔒 CORS enabled for all origins`);
  logger.log(`📡 Casdoor endpoint: ${configService.get('CASDOOR_ENDPOINT')}`);
}

bootstrap();
