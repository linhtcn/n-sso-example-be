import { Injectable } from '@nestjs/common';
import { CasdoorConfig } from './casdoor.config';
import * as jwt from 'jsonwebtoken';

/**
 * Service responsible for parsing and verifying JWT tokens
 *
 * This service exists because the Casdoor SDK's parseJwtToken method
 * hardcodes the RS256 algorithm, but our Casdoor instance uses ES256 (ECDSA).
 *
 * Following SOLID principles:
 * - Single Responsibility: Only handles JWT parsing/verification
 * - DRY: Centralized logic used by AuthService, JwtStrategy, and UserService
 */
@Injectable()
export class JwtParserService {
  constructor(private casdoorConfig: CasdoorConfig) {}

  /**
   * Parse and verify JWT token with correct algorithm support
   *
   * @param token - JWT token to parse and verify
   * @returns Decoded JWT payload with user information
   * @throws Error if token is invalid or verification fails
   */
  parseJwtToken(token: string): any {
    return jwt.verify(token, this.casdoorConfig.getCertificate(), {
      algorithms: ['ES256', 'RS256'], // Support both ECDSA and RSA
    });
  }
}
