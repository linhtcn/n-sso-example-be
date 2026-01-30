import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CasdoorConfig } from './casdoor.config';
import { JwtParserService } from './jwt-parser.service';

@Injectable()
export class AuthService {
  constructor(
    private casdoorConfig: CasdoorConfig,
    private jwtService: JwtService,
    private jwtParserService: JwtParserService,
  ) {}

  /**
   * Get Casdoor sign-in URL
   */
  getSignInUrl(redirectUri: string): string {
    const sdk = this.casdoorConfig.getSdk();
    return sdk.getSignInUrl(redirectUri);
  }

  /**
   * Get Casdoor sign-up URL
   */
  getSignUpUrl(redirectUri: string): string {
    const sdk = this.casdoorConfig.getSdk();
    return sdk.getSignUpUrl(false, redirectUri);
  }

  /**
   * Exchange OAuth code for tokens
   */
  async handleCallback(code: string) {
    try {
      const sdk = this.casdoorConfig.getSdk();

      // Exchange code for access token
      const { access_token, refresh_token } = await sdk.getAuthToken(code);

      // Parse JWT token to get user info
      const userInfo = this.jwtParserService.parseJwtToken(access_token);

      return {
        accessToken: access_token,
        refreshToken: refresh_token,
        user: userInfo,
      };
    } catch (error) {
      throw new UnauthorizedException(
        `Failed to authenticate with Casdoor: ${error.message}`,
      );
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string) {
    try {
      const sdk = this.casdoorConfig.getSdk();
      const { access_token, refresh_token } = await sdk.refreshToken(
        refreshToken,
        'read',
      );

      const userInfo = this.jwtParserService.parseJwtToken(access_token);

      return {
        accessToken: access_token,
        refreshToken: refresh_token,
        user: userInfo,
      };
    } catch (error) {
      throw new UnauthorizedException('Failed to refresh token');
    }
  }

  /**
   * Verify and parse JWT token
   */
  async verifyToken(token: string) {
    try {
      const userInfo = this.jwtParserService.parseJwtToken(token);
      return userInfo;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  /**
   * Get user profile URL
   */
  getUserProfileUrl(username: string, accessToken: string): string {
    const sdk = this.casdoorConfig.getSdk();
    return sdk.getUserProfileUrl(username, accessToken);
  }

  /**
   * Call Casdoor SSO logout API
   * This will terminate the SSO session on Casdoor side
   */
  async ssoLogout(accessToken: string): Promise<void> {
    const endpoint = this.casdoorConfig.getEndpoint();
    const TIMEOUT_MS = 5000; // 5 seconds timeout

    try {
      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

      // Call Casdoor's SSO logout endpoint with the access token
      const response = await fetch(`${endpoint}/api/sso-logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      });

      // Clear timeout if request completes
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`SSO logout failed: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.status !== 'ok') {
        throw new Error(`SSO logout failed: ${data.msg || 'Unknown error'}`);
      }
    } catch (error) {
      // Handle timeout and other errors
      if (error.name === 'AbortError') {
        console.error(`SSO logout timeout after ${TIMEOUT_MS}ms`);
      } else {
        console.error('SSO logout error:', error.message);
      }
      // Don't throw - we still want local logout to succeed
    }
  }
}
