/**
 * Copyright 2018-2020 Symlink GmbH
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




import { MsAuth } from "@symlinkde/eco-os-pk-models";
import { CustomRestError } from "@symlinkde/eco-os-pk-api";
import { IAuthentication, AUTHENTICATION_TYPES, authenticationContainer } from "../../infrastructure/authentication";

export class AuthenticationController {
  private authentication: IAuthentication;

  constructor(userRequest: MsAuth.IAuthenticationRequest) {
    authenticationContainer
      .rebind<MsAuth.IAuthenticationRequest>(AUTHENTICATION_TYPES.IAuthenticationRequest)
      .toConstantValue(<MsAuth.IAuthenticationRequest>userRequest);
    this.authentication = authenticationContainer.get(AUTHENTICATION_TYPES.IAuthentication);
  }

  public async authenticate(): Promise<boolean | CustomRestError> {
    return await this.authentication.authenticate();
  }

  public async getToken(): Promise<{ token: string; lifeTime: number } | CustomRestError> {
    return await this.authentication.getToken();
  }
}
