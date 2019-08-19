/** 
* Copyright 2018-2019 Symlink GmbH 
* 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
*  
*     http://www.apache.org/licenses/LICENSE-2.0 
* 
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
* 
*/ 

import "reflect-metadata";
import { PkCore, PkHooks, MsUser, MsAuth, PkCrypt, MsConf } from "@symlinkde/eco-os-pk-models";
import { serviceContainer, ECO_OS_PK_CORE_TYPES } from "@symlinkde/eco-os-pk-core";
import { TokenService, CryptionService } from "@symlinkde/eco-os-pk-crypt";
import { IAuthentication } from "./IAuthentication";
import { injectable, inject } from "inversify";
import { AUTHENTICATION_TYPES } from "./AuthenticationTypes";
import { apiResponseCodes, CustomRestError } from "@symlinkde/eco-os-pk-api";
import { injectUserHooks } from "@symlinkde/eco-os-pk-hooks";

@injectUserHooks
@injectable()
export class Authentication implements IAuthentication {
  public userHooks!: PkHooks.IUserHooks;
  private userAuthenticationRequest: MsAuth.IAuthenticationRequest;
  private userClient: PkCore.IEcoUserClient;
  private configClient: PkCore.IEcoConfigClient;
  private cryptService: CryptionService;
  private loadedUser: MsUser.IUser | null;

  constructor(
    @inject(AUTHENTICATION_TYPES.IAuthenticationRequest) userAuthenticationRequest: MsAuth.IAuthenticationRequest,
  ) {
    this.userAuthenticationRequest = userAuthenticationRequest;
    this.userClient = serviceContainer.get<PkCore.IEcoUserClient>(ECO_OS_PK_CORE_TYPES.IEcoUserClient);
    this.configClient = serviceContainer.get<PkCore.IEcoConfigClient>(ECO_OS_PK_CORE_TYPES.IEcoConfigClient);

    this.cryptService = new CryptionService(4);
    this.loadedUser = null;
  }

  public async authenticate(): Promise<boolean> {
    const user = await this.loadUserByEmail();
    const loginConfig = await this.loadLoginPolicies();

    await this.checkActivState(user);
    await this.validateLoginProtection(user, loginConfig);

    this.loadedUser = user;

    return await this.checkPasswords(user);
  }

  public async authenticateByApiKey(): Promise<boolean> {
    return false;
  }

  public async getToken(): Promise<{ token: string; lifeTime: number }> {
    if (this.loadedUser === null) {
      return {
        token: "",
        lifeTime: 0,
      };
    }

    const tokenConfig = await this.loadTokenSecret();
    const tokenService = new TokenService(tokenConfig.secret, tokenConfig.lifeTime);

    const token = await tokenService.generateToken(<PkCrypt.ISignToken>{
      _id: this.loadedUser._id,
      email: this.loadedUser.email,
      role: this.loadedUser.acl.role,
    });

    return {
      token,
      lifeTime: 3600,
    };
  }

  private async checkActivState(user: MsUser.IUser): Promise<void> {
    if (!user.isActive || user._id === undefined) {
      throw new CustomRestError(
        {
          code: apiResponseCodes.C802.code,
          message: apiResponseCodes.C802.message,
        },
        401,
      );
    }

    return;
  }

  private async validateLoginProtection(user: MsUser.IUser, loginConfig: MsConf.IPoliciesConfig): Promise<void> {
    if (user.loginErrorCounter >= loginConfig.maxLoginAttemps && user._id !== undefined) {
      if (user.accountLockTime !== undefined && user.accountLockTime !== null) {
        if (new Date(user.accountLockTime) < new Date()) {
          await this.userClient.updateUserById(user._id, { accountLockTime: null, loginErrorCounter: 0 });
          return;
        }

        throw new CustomRestError(
          {
            code: apiResponseCodes.C801.code,
            message: `${apiResponseCodes.C801.message} ${user.accountLockTime}`,
          },
          401,
        );
      }
      await this.userClient.updateUserById(user._id, { accountLockTime: this.calculateLockTime(loginConfig.lockTime) });

      const userCopy = { ...user };
      userCopy.accountLockTime = this.calculateLockTime(loginConfig.lockTime);
      this.userHooks.afterLookAccount(userCopy);
      throw new CustomRestError(
        {
          code: apiResponseCodes.C801.code,
          message: `account locked until ${this.calculateLockTime(loginConfig.lockTime)}`,
        },
        401,
      );
    }

    return;
  }

  private async checkPasswords(user: MsUser.IUser): Promise<boolean> {
    const result = await this.cryptService.compare(this.userAuthenticationRequest.password, user.password);

    if (user._id === undefined) {
      throw new CustomRestError(
        {
          code: 401,
          message: "authentication rejected. internal server error",
        },
        401,
      );
    }

    if (!result) {
      await this.userClient.updateUserById(user._id, { loginErrorCounter: user.loginErrorCounter + 1 });
      throw new CustomRestError(
        {
          code: apiResponseCodes.C804.code,
          message: apiResponseCodes.C804.message,
        },
        401,
      );
    } else {
      await this.userClient.updateUserById(user._id, { loginErrorCounter: 0, accountLockTime: null });
      return true;
    }
  }

  private async loadUserByEmail(): Promise<MsUser.IUser> {
    try {
      const result = await this.userClient.loadUserByEmail(this.userAuthenticationRequest.email);
      return result.data;
    } catch (err) {
      throw new CustomRestError(
        {
          code: 401,
          message: "Authentication failed",
        },
        401,
      );
    }
  }

  private async loadTokenSecret(): Promise<MsAuth.ITokenConfig> {
    const loadedConfig = await this.configClient.get("auth");
    return <MsConf.IAuthConfig>Object(loadedConfig.data.auth);
  }

  private async loadLoginPolicies(): Promise<MsConf.IPoliciesConfig> {
    const loadedConfig = await this.configClient.get("policies");
    return <MsConf.IPoliciesConfig>Object(loadedConfig.data.policies);
  }

  private calculateLockTime(duration: number): Date {
    return new Date(new Date().getTime() + duration);
  }
}
