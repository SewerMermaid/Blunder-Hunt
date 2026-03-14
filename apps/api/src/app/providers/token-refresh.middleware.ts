import { Injectable, NestMiddleware } from "@nestjs/common";
import { NextFunction, Request, Response } from "express";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { AuthService } from "../auth/auth.service";
import { InjectRedis } from "@liaoliaots/nestjs-redis";
import Redis from "ioredis";
import * as jwt from "jsonwebtoken";
import * as crypto from "crypto";

@Injectable()
export class TokenRefreshMiddleware implements NestMiddleware {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly authService: AuthService,
    @InjectRedis() private readonly redis: Redis
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    if (
      req.cookies &&
      "authenticated" in req.cookies &&
      !("access_token" in req.cookies) &&
      !("refresh_token" in req.cookies)
    ) {
      await this.authService.logout(req, res);
      return next();
    }

    if (
      req.cookies &&
      "authenticated" in req.cookies
    ) {
      if (
        !("access_token" in req.cookies) &&
        "refresh_token" in req.cookies
      ) {
        await this.renewAccessToken(req, res);
      }

      try {
        jwt.verify(req.cookies.access_token, this.configService.get<string>("JWT_SECRET"));
      } catch (e) {
        if ("refresh_token" in req.cookies) {
          await this.renewAccessToken(req, res);
        } else {
          await this.authService.logout(req, res);
        }
      }
    }

    next();
  }

  async renewAccessToken(req: Request, res: Response): Promise<boolean> {
    let refreshToken: { id: string; sessionId: string; email: string; type: "refresh" };

    try {
      refreshToken = jwt.verify(
        req.cookies["refresh_token"],
        this.configService.get<string>("JWT_SECRET")
      ) as { id: string; sessionId: string; email: string; type: "refresh" };
    } catch (e) {
      await this.authService.logout(req, res);
      return true;
    }

    const storedToken = await this.redis.get(refreshToken.sessionId);

    if (!refreshToken.sessionId || !storedToken) {
      await this.authService.logout(req, res);
      return true;
    }

    const accessToken = this.jwtService.sign(
      {
        id: refreshToken.id,
        sessionId: refreshToken.sessionId,
        email: refreshToken.email,
        type: "access"
      },
      { expiresIn: "15m" }
    );

    req.cookies["access_token"] = accessToken;
    res.cookie("access_token", accessToken, {
      httpOnly: true,
      expires: new Date(new Date().getTime() + 15 * 60000)
    });

    return false;
  }
}
