import {
  Controller,
  Get,
  Post,
  UseGuards,
  Request,
  Query,
  Body,
  Logger,
  HttpException,
  HttpStatus,
  Version,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiBody,
  ApiBearerAuth,
  ApiCookieAuth,
} from '@nestjs/swagger';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import {
  UserProfileResponseDto,
  UserDetailsResponseDto,
  UserPermissionsResponseDto,
  UserRolesResponseDto,
  CheckPermissionResponseDto,
  BatchCheckPermissionsRequestDto,
  BatchCheckPermissionsResponseDto,
} from './dto/user.dto';

@ApiTags('user')
@Controller('user')
export class UserController {
  private readonly logger = new Logger(UserController.name);

  constructor(private userService: UserService) {}

  /**
   * Get current user profile
   * GET /user/me
   * Headers: Authorization: Bearer <token>
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiOperation({ summary: 'Get current authenticated user profile' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiResponse({
    status: 200,
    description: 'User profile retrieved successfully',
    type: UserProfileResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async getCurrentUser(@Request() req) {
    this.logger.log(`Fetching profile for user: ${req.user.name}`);
    return {
      user: req.user,
    };
  }

  /**
   * Get detailed user information from Casdoor
   * GET /user/details
   * Headers: Authorization: Bearer <token>
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('details')
  @ApiOperation({ summary: 'Get detailed user information from Casdoor API' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiResponse({
    status: 200,
    description: 'User details retrieved successfully',
    type: UserDetailsResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getUserDetails(@Request() req) {
    const userId = req.user.name || req.user.id;
    this.logger.log(`Fetching detailed info for user: ${userId}`);

    const userDetails = await this.userService.getUserFromCasdoor(userId);

    if (!userDetails) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    return {
      user: userDetails,
    };
  }

  /**
   * Get user roles and permissions from Casdoor API
   * GET /user/permissions
   * Headers: Authorization: Bearer <token>
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('permissions')
  @ApiOperation({ summary: 'Get user roles and permissions from Casdoor API' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiResponse({
    status: 200,
    description: 'User permissions retrieved successfully',
    type: UserPermissionsResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async getUserPermissions(@Request() req) {
    const userId = req.user.name || req.user.id;
    this.logger.log(`Fetching permissions for user: ${userId}`);

    const rolesAndPermissions = await this.userService.getUserRolesAndPermissions(userId);

    return {
      userId,
      // Include roles/permissions from token (immediate)
      tokenRoles: req.user.roles || [],
      tokenPermissions: req.user.permissions || [],
      // Include roles/permissions from Casdoor API (authoritative)
      ...rolesAndPermissions,
    };
  }

  /**
   * Get only user roles from Casdoor
   * GET /user/roles
   * Headers: Authorization: Bearer <token>
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('roles')
  @ApiOperation({ summary: 'Get user roles from Casdoor API' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiResponse({
    status: 200,
    description: 'User roles retrieved successfully',
    type: UserRolesResponseDto,
  })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async getUserRoles(@Request() req) {
    const userId = req.user.name || req.user.id;
    this.logger.log(`Fetching roles for user: ${userId}`);

    const roles = await this.userService.getUserRoles(userId);

    return {
      userId,
      roles,
    };
  }

  /**
   * Check specific permission
   * GET /user/check-permission?resource=articles&action=read
   * Headers: Authorization: Bearer <token>
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Get('check-permission')
  @ApiOperation({ summary: 'Check if user has a specific permission' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiQuery({
    name: 'resource',
    required: true,
    description: 'Resource to check permission for',
    example: 'articles',
  })
  @ApiQuery({
    name: 'action',
    required: true,
    description: 'Action to check permission for',
    example: 'read',
  })
  @ApiResponse({
    status: 200,
    description: 'Permission check completed',
    type: CheckPermissionResponseDto,
  })
  @ApiResponse({ status: 400, description: 'resource and action query parameters are required' })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async checkPermission(
    @Request() req,
    @Query('resource') resource: string,
    @Query('action') action: string,
  ) {
    if (!resource || !action) {
      throw new HttpException(
        'resource and action query parameters are required',
        HttpStatus.BAD_REQUEST,
      );
    }

    const userId = req.user.name || req.user.id;
    this.logger.log(`Checking permission for ${userId}: ${action} on ${resource}`);

    const hasPermission = await this.userService.checkPermission(
      userId,
      resource,
      action,
    );

    return {
      userId,
      resource,
      action,
      hasPermission,
    };
  }

  /**
   * Batch check multiple permissions
   * POST /user/check-permissions
   * Headers: Authorization: Bearer <token>
   * Body: {
   *   checks: [
   *     { resource: "articles", action: "read" },
   *     { resource: "articles", action: "write" },
   *     { resource: "users", action: "delete" }
   *   ]
   * }
   */
  @Version('1')
  @UseGuards(JwtAuthGuard)
  @Post('check-permissions')
  @ApiOperation({ summary: 'Batch check multiple permissions at once' })
  @ApiBearerAuth('JWT-auth')
  @ApiCookieAuth('cookie-auth')
  @ApiBody({ type: BatchCheckPermissionsRequestDto })
  @ApiResponse({
    status: 200,
    description: 'Permission checks completed',
    type: BatchCheckPermissionsResponseDto,
  })
  @ApiResponse({ status: 400, description: 'checks array is required in request body' })
  @ApiResponse({ status: 401, description: 'Unauthorized - Invalid or missing token' })
  async checkPermissions(
    @Request() req,
    @Body('checks') checks: Array<{ resource: string; action: string }>,
  ) {
    if (!checks || !Array.isArray(checks) || checks.length === 0) {
      throw new HttpException(
        'checks array is required in request body',
        HttpStatus.BAD_REQUEST,
      );
    }

    const userId = req.user.name || req.user.id;
    this.logger.log(`Batch checking ${checks.length} permissions for user: ${userId}`);

    const results = await this.userService.checkPermissions(userId, checks);

    return {
      userId,
      checks: results,
    };
  }
}
