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



import { IAuthentication, AUTHENTICATION_TYPES, authenticationContainer } from "../../infrastructure/authentication";
import { CustomRestError } from "@symlinkde/eco-os-pk-api";
import { Request } from "express";
import { Log, LogLevel } from "@symlinkde/eco-os-pk-log";

export class ApiKeyController {
  private authentication: IAuthentication;

  constructor() {
    this.authentication = authenticationContainer.get(AUTHENTICATION_TYPES.IAuthentication);
  }

  public async authenticateByApiKey(req: Request): Promise<void | CustomRestError> {
    try {
      const hasAccess = await this.authentication.authenticateByApiKey(req.body.apiKey);
      if (!hasAccess) {
        throw new CustomRestError(
          {
            code: 401,
            message: "api key is not valid",
          },
          401,
        );
      }

      return;
    } catch (err) {
      Log.log(err, LogLevel.error);
      throw new CustomRestError(
        {
          code: 401,
          message: "can't auth by token",
        },
        401,
      );
    }
  }
}
