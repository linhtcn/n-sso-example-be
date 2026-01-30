import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { JwtParserService } from './jwt-parser.service';

@Injectable()
export class TokenBlacklistService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TokenBlacklistService.name);
  private blacklist: Map<string, number> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor(private readonly jwtParserService: JwtParserService) {}

  onModuleInit() {
    // Run cleanup every 5 minutes to remove expired tokens
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000);

    this.logger.log('Token blacklist service initialized');
  }

  onModuleDestroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.logger.log('Token blacklist service destroyed');
  }

  /**
   * Add token to blacklist with expiration
   */
  async blacklistToken(accessToken: string): Promise<void> {
    try {
      // Parse token to get expiration time
      const decoded = this.jwtParserService.parseJwtToken(accessToken);
      const expiresAt = decoded.exp; // Unix timestamp

      // Only blacklist if not already expired
      const now = Math.floor(Date.now() / 1000);
      if (expiresAt > now) {
        this.blacklist.set(accessToken, expiresAt);
        this.logger.debug(`Token blacklisted, expires at ${new Date(expiresAt * 1000).toISOString()}`);
      } else {
        this.logger.debug('Token already expired, not adding to blacklist');
      }
    } catch (error) {
      this.logger.error(`Failed to blacklist token: ${error.message}`);
      // Don't throw - logout should continue even if blacklisting fails
    }
  }

  /**
   * Check if token is blacklisted
   */
  async isBlacklisted(accessToken: string): Promise<boolean> {
    if (!this.blacklist.has(accessToken)) {
      return false;
    }

    // Check if token has expired
    const expiresAt = this.blacklist.get(accessToken);
    const now = Math.floor(Date.now() / 1000);

    if (expiresAt <= now) {
      // Token expired, remove from blacklist
      this.blacklist.delete(accessToken);
      this.logger.debug('Token expired and removed from blacklist');
      return false;
    }

    return true;
  }

  /**
   * Remove expired tokens from blacklist
   */
  private cleanup(): void {
    const now = Math.floor(Date.now() / 1000);
    let cleaned = 0;

    for (const [token, expiresAt] of this.blacklist.entries()) {
      if (expiresAt <= now) {
        this.blacklist.delete(token);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.log(`Cleaned ${cleaned} expired tokens from blacklist`);
    }

    this.logger.debug(`Blacklist cleanup completed. Current size: ${this.blacklist.size}`);
  }

  /**
   * Get blacklist statistics (for monitoring)
   */
  getStats() {
    return {
      size: this.blacklist.size,
      tokens: Array.from(this.blacklist.entries()).map(([token, exp]) => ({
        token: token.substring(0, 20) + '...',
        expiresAt: new Date(exp * 1000).toISOString(),
      })),
    };
  }
}
