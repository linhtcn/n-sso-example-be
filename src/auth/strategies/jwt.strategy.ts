import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { CasdoorConfig } from '../casdoor.config';
import { TokenBlacklistService } from '../token-blacklist.service';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly casdoorConfig: CasdoorConfig,
    private readonly tokenBlacklistService: TokenBlacklistService,
  ) {
    super({
      // Support both Authorization header and cookies
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        JwtStrategy.extractJwtFromCookie,
      ]),
      ignoreExpiration: false,
      secretOrKey: casdoorConfig.getCertificate(),
      algorithms: ['ES256', 'RS256'], // Support both ECDSA and RSA
      passReqToCallback: true, // Enable request in validate()
    });
  }

  /**
   * Extract JWT from HTTP-only cookie
   */
  private static extractJwtFromCookie(req: Request): string | null {
    if (req.cookies && req.cookies.access_token) {
      return req.cookies.access_token;
    }
    return null;
  }

  /**
   * Extract token from request (Authorization header or cookie)
   */
  private extractTokenFromRequest(request: any): string | null {
    // Try Authorization header first
    const authHeader = request.headers?.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Try cookie
    if (request.cookies?.access_token) {
      return request.cookies.access_token;
    }

    return null;
  }

  async validate(request: any, payload: any) {
    // At this point, passport-jwt has already verified the token
    // with the Casdoor certificate and correct algorithms

    // Extract token from request
    const token = this.extractTokenFromRequest(request);

    // Check if token is blacklisted
    if (token) {
      const isBlacklisted = await this.tokenBlacklistService.isBlacklisted(token);
      if (isBlacklisted) {
        throw new UnauthorizedException('Token has been revoked');
      }
    }

    // The payload contains the decoded JWT user information
    return payload;
  }
}
