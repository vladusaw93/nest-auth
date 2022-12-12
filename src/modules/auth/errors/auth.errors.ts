import { ForbiddenException, HttpException, HttpStatus } from '@nestjs/common';

export const IncorrectCredentialsError = () => {
  throw new HttpException('Credentials incorrect!', HttpStatus.BAD_REQUEST);
};

export const InvalidDataError = () => {
  throw new HttpException('Invalid data!', HttpStatus.BAD_REQUEST);
};

export const TokenExpiredError = () => {
  throw new HttpException('Token expired!', HttpStatus.BAD_REQUEST);
};

export const AccessDeniedError = () => {
  throw new ForbiddenException('Access Denied!');
};
