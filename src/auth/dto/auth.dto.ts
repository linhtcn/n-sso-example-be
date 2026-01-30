import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsBoolean, IsOptional, IsUrl } from 'class-validator';

export class SignInUrlQueryDto {
  @ApiProperty({
    description: 'The redirect URI after successful authentication',
    example: 'http://localhost:3000/callback',
  })
  @IsUrl()
  @IsNotEmpty()
  redirect_uri: string;
}

export class SignInUrlResponseDto {
  @ApiProperty({
    description: 'The Casdoor sign-in URL',
    example: 'https://casdoor.example.com/login/oauth/authorize?...',
  })
  url: string;
}

export class CallbackRequestDto {
  @ApiProperty({
    description: 'OAuth authorization code from Casdoor',
    example: '1234567890abcdef',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiPropertyOptional({
    description: 'Whether to use HTTP-only cookies for token storage',
    example: false,
    default: false,
  })
  @IsBoolean()
  @IsOptional()
  useCookies?: boolean;
}

export class UserResponseDto {
  @ApiProperty({ description: 'User ID' })
  name: string;

  @ApiProperty({ description: 'User display name' })
  displayName: string;

  @ApiProperty({ description: 'User email' })
  email: string;

  @ApiPropertyOptional({ description: 'User avatar URL' })
  avatar?: string;

  @ApiPropertyOptional({ description: 'User roles', type: [String] })
  roles?: string[];

  @ApiPropertyOptional({ description: 'User permissions', type: [String] })
  permissions?: string[];
}

export class CallbackResponseDto {
  @ApiProperty({ description: 'JWT access token' })
  accessToken: string;

  @ApiProperty({ description: 'JWT refresh token' })
  refreshToken: string;

  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;
}

export class CallbackCookieResponseDto {
  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;

  @ApiProperty({ description: 'Success message' })
  message: string;
}

export class RefreshTokenRequestDto {
  @ApiPropertyOptional({
    description: 'Refresh token (required if not using cookies)',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  @IsOptional()
  refreshToken?: string;

  @ApiPropertyOptional({
    description: 'Whether to use HTTP-only cookies for token storage',
    example: false,
    default: false,
  })
  @IsBoolean()
  @IsOptional()
  useCookies?: boolean;
}

export class RefreshTokenResponseDto {
  @ApiProperty({ description: 'New JWT access token' })
  accessToken: string;

  @ApiProperty({ description: 'New JWT refresh token' })
  refreshToken: string;

  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;
}

export class RefreshTokenCookieResponseDto {
  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;

  @ApiProperty({ description: 'Success message' })
  message: string;
}

export class VerifyTokenResponseDto {
  @ApiProperty({ description: 'User information', type: UserResponseDto })
  user: UserResponseDto;
}

export class LogoutResponseDto {
  @ApiProperty({ description: 'Success message', example: 'Logged out successfully' })
  message: string;
}
