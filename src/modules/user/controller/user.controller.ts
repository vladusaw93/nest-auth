import { Controller, Get } from '@nestjs/common';
import { UserService } from '../service';
import { Roles } from '../../common/decorators';
import { Role } from '../../common/constants';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Roles(Role.Admin)
  @Get('all')
  async getCurrentUser() {
    return this.userService.getUsers();
  }
}
