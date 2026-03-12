import { Injectable } from "@angular/core";
import { CanActivate, Router } from "@angular/router";
import { CookieService } from "ngx-cookie";
import { UsersService } from "../shared/http/users.service";

@Injectable({
  providedIn: "root"
})
export class AuthGuardService implements CanActivate {
  constructor(
    private cookieService: CookieService,
    private usersService: UsersService,
    public router: Router
  ) {}

  async canActivate(): Promise<boolean> {
    if (!this.cookieService.get("authenticated")) {
      await this.router.navigate([""]);
      return false;
    }

    const user = await this.usersService.myUser();

    if (!user) {
      this.cookieService.remove("authenticated");
      await this.router.navigate([""]);
      return false;
    }

    return true;
  }
}
