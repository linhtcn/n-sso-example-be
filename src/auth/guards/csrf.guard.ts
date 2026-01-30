import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class CsrfGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // Skip CSRF check if using Bearer token
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return true; // Bearer tokens are not vulnerable to CSRF
    }

    // If using cookies, CSRF token is required
    if (request.cookies?.access_token) {
      const csrfToken = request.headers['x-csrf-token'] || request.body?._csrf;

      if (!csrfToken) {
        throw new ForbiddenException('CSRF token missing');
      }

      // Validate CSRF token (handled by csurf middleware)
      return true;
    }

    // No authentication method found - allow to proceed
    // (will be caught by JWT guard if protected)
    return true;
  }
}
