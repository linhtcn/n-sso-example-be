import {
  Controller,
  Get,
  Post,
  Query,
  Body,
  UseGuards,
  Request,
  Response,
  Logger,
  HttpStatus,
  HttpException,
  Version,
} from '@nestjs/common';
import { Response as ExpressResponse } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiBody,
  ApiBearerAuth,
  ApiCookieAuth,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ConfigService } from '@nestjs/config';
import { TokenBlacklistService } from './token-blacklist.service';
import { JwtParserService } from './jwt-parser.service';
import {
  SignInUrlResponseDto,
  CallbackRequestDto,
  CallbackResponseDto,
  CallbackCookieResponseDto,
  RefreshTokenRequestDto,
  RefreshTokenResponseDto,
  RefreshTokenCookieResponseDto,
  VerifyTokenResponseDto,
  LogoutResponseDto,
} from './dto/auth.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private authService: AuthService,
    private configService: ConfigService,
    private tokenBlacklistService: TokenBlacklistService,
    private jwtParserService: JwtParserService,
  ) {}

  /**
   * Get Casdoor sign-in URL
   * GET /auth/signin-url?redirect_uri=http://localhost:3000/callback
   */
  @Version('1')
  @Get('signin-url')
  @ApiOperation({ summary: 'Get Casdoor sign-in URL' })
  @ApiQuery({
    name: 'redirect_uri',
    required: true,
    description: 'The redirect URI after successful authentication',
    example: 'http://localhost:3000/callback',
  })
  @ApiResponse({
    status: 200,
    description: 'Sign-in URL generated successfully',
    type: SignInUrlResponseDto,
  })
  @ApiResponse({ status: 400, description: 'redirect_uri is required' })
  getSignInUrl(@Query('redirect_uri') redirectUri: string) {
    if (!redirectUri) {
      throw new HttpException('redirect_uri is required', HttpStatus.BAD_REQUEST);
    }

    const url = this.authService.getSignInUrl(redirectUri);
    this.logger.log(`Generated sign-in URL for redirect: ${redirectUri}`);
    return { url };
  }

  /**
   * Get Casdoor sign-up URL
   * GET /auth/signup-url?redirect_uri=http://localhost:3000/callback
   */
  @Version('1')
  @Get('signup-url')
  @ApiOperation({ summary: 'Get Casdoor sign-up URL' })
  @ApiQuery({
    name: 'redirect_uri',
    required: true,
    description: 'The redirect URI after successful registration',
    example: 'http://localhost:3000/callback',
  })
  @ApiResponse({
    status: 200,
    description: 'Sign-up URL generated successfully',
    type: SignInUrlResponseDto,
  })
  @ApiResponse({ status: 400, description: 'redirect_uri is required' })
  getSignUpUrl(@Query('redirect_uri') redirectUri: string) {
    if (!redirectUri) {
      throw new HttpException('redirect_uri is required', HttpStatus.BAD_REQUEST);
    }

    const url = this.authService.getSignUpUrl(redirectUri);
    this.logger.log(`Generated sign-up URL for redirect: ${redirectUri}`);
    return { url };
  }

  /**
   * Handle OAuth callback - receives code and state from query parameters
   * POST /auth/callback?code=...&state=...
   */
  @Version('1')
  @Post('callback')
  @ApiOperation({ summary: 'Handle OAuth callback and authenticate user' })
  @ApiQuery({ name: 'code', required: true, description: 'Authorization code from OAuth provider' })
  @ApiQuery({ name: 'state', required: false, description: 'OAuth state parameter' })
  @ApiQuery({ name: 'useCookies', required: false, description: 'Whether to use cookies for authentication' })
  @ApiResponse({
    status: 200,
    description: 'Authentication successful (with tokens in response body)',
    type: CallbackResponseDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Authentication successful (with tokens in cookies)',
    type: CallbackCookieResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Authorization code is required' })
  @ApiResponse({ status: 401, description: 'Authentication failed' })
  async handleCallback(
    @Query('code') code: string,
    @Query('state') state: string | undefined,
    @Response({ passthrough: true }) res: ExpressResponse,
    @Query('useCookies') useCookies?: string,
  ) {
    if (!code) {
      throw new HttpException('Authorization code is required', HttpStatus.BAD_REQUEST);
    }

    try {
      const result = await this.authService.handleCallback(code);
      this.logger.log(`User authenticated successfully: ${result.user}`);

      // verify state

      // If cookies are enabled, set HTTP-only cookies
      const shouldUseCookies = useCookies === 'true';
      if (shouldUseCookies) {
        const isSecure = this.configService.get('COOKIE_SECURE') === 'true';
        const sameSite = this.configService.get('COOKIE_SAME_SITE') || 'lax';

        res.cookie('access_token', result.accessToken, {
          httpOnly: true,
          secure: isSecure,
          sameSite: sameSite as any,
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.cookie('refresh_token', result.refreshToken, {
          httpOnly: true,
          secure: isSecure,
          sameSite: sameSite as any,
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        });

        // Don't send tokens in response body when using cookies
        return {
          user: result.user,
          message: 'Authentication successful',
        };
      }

      return result;
    } catch (error) {
      this.logger.error(`Authentication failed: ${error.message}`, error.stack);
      throw new HttpException(
        'Authentication failed',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  /**
   * Refresh access token
   * POST /auth/refresh
   * Body: { refreshToken?: string, useCookies?: boolean }
   * Cookie: refresh_token (if useCookies=true)
   */
  @Version('1')
  @Post('refresh')
  @ApiOperation({ summary: 'Refresh access token using refresh token' })
  @ApiBody({ type: RefreshTokenRequestDto })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully (with tokens in response body)',
    type: RefreshTokenResponseDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Token refreshed successfully (with tokens in cookies)',
    type: RefreshTokenCookieResponseDto,
  })
  @ApiResponse({ status: 400, description: 'Refresh token is required' })
  @ApiResponse({ status: 401, description: 'Token refresh failed' })
  async refreshToken(
    @Body('refreshToken') refreshToken: string,
    @Body('useCookies') useCookies: boolean = false,
    @Request() req,
    @Response({ passthrough: true }) res: ExpressResponse,
  ) {
    // Get refresh token from cookie or body
    const token = useCookies ? req.cookies?.refresh_token : refreshToken;

    if (!token) {
      throw new HttpException(
        'Refresh token is required',
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      const result = await this.authService.refreshToken(token);
      this.logger.log(`Token refreshed for user: ${result.user.name}`);

      // If cookies are enabled, update HTTP-only cookies
      if (useCookies) {
        const isSecure = this.configService.get('COOKIE_SECURE') === 'true';
        const sameSite = this.configService.get('COOKIE_SAME_SITE') || 'lax';

        res.cookie('access_token', result.accessToken, {
          httpOnly: true,
          secure: isSecure,
          sameSite: sameSite as any,
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.cookie('refresh_token', result.refreshToken, {
          httpOnly: true,
          secure: isSecure,
          sameSite: sameSite as any,
          maxAge: 30 * 24 * 60 * 60 * 1000,
        });

        return {
          user: result.user,
          message: 'Token refreshed successfully',
        };
      }

      return result;
    } catch (error) {
      this.logger.error(`Token refresh failed: ${error.message}`, error.stack);
      throw new HttpException(
        'Token refresh failed',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  /**
   * Verify token and get user info
   * GET /auth/verify
   * Headers: Authorization: Bearer <token>
   * Cookie: access_token (alternative)
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('verify')
  @ApiOperation({ summary: 'Verify JWT token and get user information' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiResponse({
    status: 200,
    description: 'Token is valid',
    type: VerifyTokenResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async verifyToken(@Request() req) {
    this.logger.log(`Token verified for user: ${req.user.name}`);
    return { user: req.user };
  }

  /**
   * Get CSRF token for cookie-based authentication
   * GET /auth/csrf-token
   */
  @Version('1')
  @Get('csrf-token')
  @ApiOperation({ summary: 'Get CSRF token for cookie-based authentication' })
  @ApiResponse({
    status: 200,
    description: 'CSRF token generated successfully',
    schema: {
      type: 'object',
      properties: {
        csrfToken: { type: 'string' },
        message: { type: 'string' },
      },
    },
  })
  getCsrfToken(@Request() req) {
    // csurf middleware adds req.csrfToken() method
    return {
      csrfToken: req.csrfToken(),
      message: 'Include this token in X-CSRF-Token header or _csrf body parameter',
    };
  }

  /**
   * Logout - clear cookies, invalidate session, and logout from SSO
   * POST /auth/logout
   * Headers: Authorization: Bearer <token> (optional but recommended for SSO logout)
   */
  @Version('1')
  @Post('logout')
  @ApiOperation({ summary: 'Logout user, clear session/cookies, and terminate SSO session' })
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully',
    type: LogoutResponseDto,
  })
  async logout(
    @Response({ passthrough: true }) res: ExpressResponse,
    @Request() req,
  ) {
    // Get access token from Authorization header or cookies
    const authHeader = req.headers.authorization;
    const accessToken = authHeader?.replace('Bearer ', '') || req.cookies?.access_token;

    let userId: string;
    let username: string;
    let ssoLogoutSuccess = false;

    // Extract user info from token before logout for logging
    if (accessToken) {
      try {
        const userInfo = this.jwtParserService.parseJwtToken(accessToken);
        userId = userInfo.id;
        username = userInfo.name;
      } catch (error) {
        this.logger.warn(`Failed to parse token for logging: ${error.message}`);
      }

      // STEP 1: Blacklist token IMMEDIATELY (before SSO logout)
      await this.tokenBlacklistService.blacklistToken(accessToken);
      this.logger.log({
        event: 'token_blacklisted',
        userId,
        username,
        timestamp: new Date().toISOString(),
        ip: req.ip,
      });

      // STEP 2: Call SSO logout (may fail, but token already blacklisted)
      try {
        await this.authService.ssoLogout(accessToken);
        ssoLogoutSuccess = true;
        this.logger.log({
          event: 'sso_logout_success',
          userId,
          username,
          timestamp: new Date().toISOString(),
          ip: req.ip,
        });
      } catch (error) {
        this.logger.error({
          event: 'sso_logout_failed',
          userId,
          username,
          error: error.message,
          timestamp: new Date().toISOString(),
          ip: req.ip,
        });
        // Continue with local logout even if SSO logout fails
      }
    }

    // Clear cookies
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    // Destroy session if exists
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          this.logger.error({
            event: 'session_destruction_failed',
            userId,
            username,
            error: err.message,
            timestamp: new Date().toISOString(),
          });
        }
      });
    }

    // Log successful logout with full context
    this.logger.log({
      event: 'user_logout_complete',
      userId,
      username,
      ssoLogoutSuccess,
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return { message: 'Logged out successfully' };
  }
}
