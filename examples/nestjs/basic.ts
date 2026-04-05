import { Controller, Get, Module, Req } from "@nestjs/common";
import type { Request } from "express";
import { CloudflareAccessGuard, Public } from "cloudflare-access/nestjs";
import { APP_GUARD } from "@nestjs/core";

@Controller("api")
export class ApiController {
  @Get("protected")
  getProtected(@Req() req: Request) {
    return {
      message: `Hello ${req.user?.email}`,
      userId: req.user?.userId,
      country: req.user?.country,
    };
  }

  @Public()
  @Get("public")
  getPublic() {
    return { message: "This is a public endpoint" };
  }
}

@Module({
  controllers: [ApiController],
  providers: [
    {
      provide: APP_GUARD,
      useFactory: () =>
        new CloudflareAccessGuard({
          accessConfig: {
            teamDomain: "https://yourteam.cloudflareaccess.com",
            audTag: "your-audience-tag",
          },
        }),
    },
  ],
})
export class AppModule {}
