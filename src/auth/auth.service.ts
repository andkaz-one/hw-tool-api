import { ForbiddenException, Injectable } from '@nestjs/common';
import { DbService } from 'src/db/db.service';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(private db: DbService,
                private jwtService: JwtService,
                 private configService: ConfigService) {}

    private hashData(data: string) {
        return bcrypt.hash(data, 10);
    } 

    async updateRtHashOnUser(userId: number, rt: string) {
        const hash = await this.hashData(rt)
        await this.db.user.update({
            where: {id: userId},
            data: {hashedRt: hash}
        })
    }

    //register
    async register(dto: RegisterDto): Promise<Tokens> {
        const hashPass = await this.hashData(dto.password);
        const newUser = await this.db.user.create(
            {
                data: {
                    name: dto.name,
                    email: dto.email,
                    hashedPass: hashPass
                }
            }
        )
        const tokens = await this.signTokens(newUser.id, newUser.email)
        await this.updateRtHashOnUser(newUser.id, tokens.refresh_token);
        return tokens
    }
    
    //login
    async login(dto: LoginDto): Promise<any> {
        const user = await this.db.user.findUnique({
            where: {
                email: dto.email
            }
        });

        if (!user) throw new ForbiddenException("You don't have permission to access this resource.");
        const passworCompare = await bcrypt.compare(dto.password, user.hashedPass);
        if (!passworCompare) throw new ForbiddenException("You don't have permission to access this resource.");

        const tokens = await this.signTokens(user.id, user.email)
        await this.updateRtHashOnUser(user.id, tokens.refresh_token);
        return {tokens, user: {id: user.id, email: user.email, isAdmin: user.isAdmin, name: user.name}};
    }
    //logout
    async logout(userId: number) {
        await this.db.user.updateMany({
            where: {
                id: userId,
                hashedRt: {
                    not: null
                }
            },
            data: {
                hashedRt: null
            }
        })
    }
    
    //refreshRt
    async refreshTokens(userId: number, userRt: string) {
        const user  = await this.db.user.findUnique({
            where: {
                id: userId
            }
        }) 

        if (!user) throw new ForbiddenException('Access Denied');

        const compareUserRt = await bcrypt.compare(userRt, user.hashedRt);

        if (!compareUserRt) throw new ForbiddenException('Access Denied');

        const tokens = await this.signTokens(user.id, user.email)
        await this.updateRtHashOnUser(user.id, tokens.refresh_token);
        return tokens;
    }


    async signTokens(userId: number, email: string) {
        const [at, rt] = await Promise.all([
            this.jwtService.signAsync({
                sub: userId,
                email,
    
            }, {
                expiresIn: 60 * 30,
                secret: this.configService.get<string>('AT_SECRET')    
            }),
            this.jwtService.signAsync({
                sub: userId,
                email,    
            }, {
                expiresIn: 60 * 60 * 24 * 7,
                secret: this.configService.get<string>('RT_SECRET')    
            })
        ])

        return {
            access_token: at,
            refresh_token: rt
        }
       
    }
}
