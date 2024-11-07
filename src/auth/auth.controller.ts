import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    //register
    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() dto: RegisterDto): Promise<Tokens> {
        return this.authService.register(dto);
    }

    //login
    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(@Body() dto: LoginDto): Promise<any> {
        return this.authService.login(dto);
    }
    
    //logout
    @UseGuards(AuthGuard('jwt-access'))
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    async logout(@Req() request: Request){
        const user = request['user']
        return this.authService.logout(user['sub'])

    }

    //refreshRt
    @UseGuards(AuthGuard('jwt-refresh'))
    @Post('refresh-rt')
    @HttpCode(HttpStatus.OK)
    async refreshTokens(@Req() request: Request) {
        const user = request['user'];
        return this.authService.refreshTokens(user['sub'], user['refreshToken']);
    }

    //check user
    @UseGuards(AuthGuard('jwt-access'))
    @Get('me')
    @HttpCode(HttpStatus.OK)
    async getLoggedUser(@Req() request: Request) {
        const user = request['user'];
        return this.authService.checkUser(user);
    }
}
