import { Injectable, Logger } from '@nestjs/common';
import { CasdoorConfig } from '../auth/casdoor.config';
import { JwtParserService } from '../auth/jwt-parser.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    private casdoorConfig: CasdoorConfig,
    private jwtParserService: JwtParserService,
    private configService: ConfigService,
  ) {}

  /**
   * Get user information from Casdoor token
   */
  async getUserInfo(token: string) {
    const userInfo = this.jwtParserService.parseJwtToken(token);
    return userInfo;
  }

  /**
   * Get detailed user information from Casdoor API
   */
  async getUserFromCasdoor(userId: string): Promise<any> {
    const sdk = this.casdoorConfig.getSdk();
    const orgName = this.configService.get('CASDOOR_ORGANIZATION_NAME');

    try {
      // Fetch user details from Casdoor API
      const response = await sdk.getUser(`${orgName}/${userId}`);

      if (response && response.data && response.data.data) {
        return response.data.data;
      }

      this.logger.warn(`User not found in Casdoor: ${userId}`);
      return null;
    } catch (error) {
      this.logger.error(`Failed to fetch user from Casdoor: ${error.message}`, error.stack);
      return null;
    }
  }

  /**
   * Get user roles from Casdoor API
   */
  async getUserRoles(userId: string) {
    const sdk = this.casdoorConfig.getSdk();

    try {
      // Get user details which include roles information
      const user = await this.getUserFromCasdoor(userId);

      if (user && user.roles) {
        return user.roles;
      }

      return [];
    } catch (error) {
      this.logger.error(`Failed to fetch roles from Casdoor: ${error.message}`, error.stack);
      return [];
    }
  }

  /**
   * Get user permissions from Casdoor API
   */
  async getUserPermissions(userId: string) {
    try {
      // Get user details which include permissions
      const user = await this.getUserFromCasdoor(userId);

      if (user && user.permissions) {
        return user.permissions;
      }

      return [];
    } catch (error) {
      this.logger.error(`Failed to fetch permissions from Casdoor: ${error.message}`, error.stack);
      return [];
    }
  }

  /**
   * Get user roles and permissions (combined)
   */
  async getUserRolesAndPermissions(userId: string) {
    try {
      this.logger.log(`Fetching roles and permissions for user: ${userId}`);

      const [roles, permissions] = await Promise.all([
        this.getUserRoles(userId),
        this.getUserPermissions(userId),
      ]);

      return {
        roles,
        permissions,
      };
    } catch (error) {
      this.logger.error(`Failed to fetch roles and permissions: ${error.message}`, error.stack);
      return {
        roles: [],
        permissions: [],
      };
    }
  }

  /**
   * Check if user has specific permission using Casbin enforcement
   */
  async checkPermission(
    userId: string,
    resource: string,
    action: string,
  ): Promise<boolean> {
    const sdk = this.casdoorConfig.getSdk();
    const orgName = this.configService.get('CASDOOR_ORGANIZATION_NAME');

    try {
      // Use Casdoor's enforce API to check permissions
      // Format: enforce(permissionId, modelId, resourceId, action, owner, request)
      const permissionId = `${orgName}/permission-${resource}`;
      const modelId = `${orgName}/built-in`;
      const resourceId = resource;

      this.logger.log(`Checking permission for user ${userId}: ${action} on ${resource}`);

      const hasPermission = await sdk.enforce(
        permissionId,
        modelId,
        resourceId,
        action,
        orgName,
        [userId, resource, action],
      );

      this.logger.log(`Permission check result for ${userId}: ${hasPermission}`);
      return hasPermission;
    } catch (error) {
      this.logger.error(`Permission check failed: ${error.message}`, error.stack);

      // Fallback: Check user permissions manually
      const permissions = await this.getUserPermissions(userId);
      const hasPermission = permissions.some(
        (perm: any) =>
          perm.resource === resource &&
          (perm.actions?.includes(action) || perm.actions?.includes('*')),
      );

      return hasPermission;
    }
  }

  /**
   * Check multiple permissions at once (batch)
   */
  async checkPermissions(
    userId: string,
    checks: Array<{ resource: string; action: string }>,
  ) {
    const sdk = this.casdoorConfig.getSdk();
    const orgName = this.configService.get('CASDOOR_ORGANIZATION_NAME');

    try {
      const requests = checks.map((check) => [
        userId,
        check.resource,
        check.action,
      ]);

      const permissionId = `${orgName}/batch-permission`;
      const modelId = `${orgName}/built-in`;

      this.logger.log(`Batch checking ${checks.length} permissions for user ${userId}`);

      const results = await sdk.batchEnforce(
        permissionId,
        modelId,
        'resource',
        'action',
        orgName,
        requests,
      );

      // Map results to original checks
      return checks.map((check, index) => ({
        resource: check.resource,
        action: check.action,
        allowed: results[index] && results[index][0],
      }));
    } catch (error) {
      this.logger.error(`Batch permission check failed: ${error.message}`, error.stack);

      // Fallback: Check individually
      const results = await Promise.all(
        checks.map((check) =>
          this.checkPermission(userId, check.resource, check.action),
        ),
      );

      return checks.map((check, index) => ({
        resource: check.resource,
        action: check.action,
        allowed: results[index],
      }));
    }
  }
}
