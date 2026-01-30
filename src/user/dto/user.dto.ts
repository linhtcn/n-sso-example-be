import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

export class UserProfileResponseDto {
  @ApiProperty({ description: 'User information' })
  user: any;
}

export class UserDetailsResponseDto {
  @ApiProperty({ description: 'Detailed user information from Casdoor' })
  user: any;
}

export class UserPermissionsResponseDto {
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @ApiProperty({ description: 'Roles from JWT token', type: [String] })
  tokenRoles: string[];

  @ApiProperty({ description: 'Permissions from JWT token', type: [String] })
  tokenPermissions: string[];

  @ApiProperty({ description: 'Roles from Casdoor API', type: [Object] })
  roles: any[];

  @ApiProperty({ description: 'Permissions from Casdoor API', type: [Object] })
  permissions: any[];
}

export class UserRolesResponseDto {
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @ApiProperty({ description: 'User roles', type: [Object] })
  roles: any[];
}

export class CheckPermissionQueryDto {
  @ApiProperty({
    description: 'Resource to check permission for',
    example: 'articles',
  })
  @IsString()
  @IsNotEmpty()
  resource: string;

  @ApiProperty({
    description: 'Action to check permission for',
    example: 'read',
  })
  @IsString()
  @IsNotEmpty()
  action: string;
}

export class CheckPermissionResponseDto {
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @ApiProperty({ description: 'Resource checked', example: 'articles' })
  resource: string;

  @ApiProperty({ description: 'Action checked', example: 'read' })
  action: string;

  @ApiProperty({ description: 'Whether user has permission', example: true })
  hasPermission: boolean;
}

export class PermissionCheckDto {
  @ApiProperty({ description: 'Resource to check', example: 'articles' })
  @IsString()
  @IsNotEmpty()
  resource: string;

  @ApiProperty({ description: 'Action to check', example: 'read' })
  @IsString()
  @IsNotEmpty()
  action: string;
}

export class BatchCheckPermissionsRequestDto {
  @ApiProperty({
    description: 'Array of permission checks',
    type: [PermissionCheckDto],
    example: [
      { resource: 'articles', action: 'read' },
      { resource: 'articles', action: 'write' },
      { resource: 'users', action: 'delete' },
    ],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PermissionCheckDto)
  checks: PermissionCheckDto[];
}

export class PermissionCheckResultDto {
  @ApiProperty({ description: 'Resource checked', example: 'articles' })
  resource: string;

  @ApiProperty({ description: 'Action checked', example: 'read' })
  action: string;

  @ApiProperty({ description: 'Whether permission is allowed', example: true })
  allowed: boolean;
}

export class BatchCheckPermissionsResponseDto {
  @ApiProperty({ description: 'User ID' })
  userId: string;

  @ApiProperty({
    description: 'Array of permission check results',
    type: [PermissionCheckResultDto],
  })
  checks: PermissionCheckResultDto[];
}
