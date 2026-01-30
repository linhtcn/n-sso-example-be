import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body } = request;
    const now = Date.now();

    // Log incoming request
    this.logger.log(`Incoming Request: ${method} ${url}`);

    if (process.env.NODE_ENV !== 'production') {
      this.logger.debug(`Request Body: ${JSON.stringify(body)}`);
    }

    return next.handle().pipe(
      tap((data) => {
        const response = context.switchToHttp().getResponse();
        const { statusCode } = response;
        const responseTime = Date.now() - now;

        this.logger.log(
          `Response: ${method} ${url} ${statusCode} - ${responseTime}ms`,
        );

        if (process.env.NODE_ENV !== 'production') {
          this.logger.debug(`Response Data: ${JSON.stringify(data)}`);
        }
      }),
    );
  }
}
