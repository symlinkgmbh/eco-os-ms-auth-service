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



import { AbstractRoutes, injectValidatorService } from "@symlinkde/eco-os-pk-api";
import { Application, Request, Response, NextFunction } from "express";
import { AuthenticationController } from "../controllers/AuthenticationController";
import { ApiKeyController } from "../controllers/ApiKeyController";
import { PkApi, MsAuth } from "@symlinkde/eco-os-pk-models";

@injectValidatorService
export class AuthenticationRoute extends AbstractRoutes implements PkApi.IRoute {
  private validatorService!: PkApi.IValidator;
  private apiKeyController: ApiKeyController;
  private postAuthPattern: PkApi.IValidatorPattern = {
    email: "",
    password: "",
  };

  private postAuthApiKeyPattern: PkApi.IValidatorPattern = {
    apiKey: "",
  };

  constructor(app: Application) {
    super(app);
    this.apiKeyController = new ApiKeyController();
    this.activate();
  }

  public activate(): void {
    this.auth();
    this.authByApiKey();
  }

  private auth(): void {
    this.getApp()
      .route("/authenticate")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postAuthPattern);
        const authenticationController = new AuthenticationController(req.body as MsAuth.IAuthenticationRequest);
        authenticationController
          .authenticate()
          .then(() => {
            authenticationController
              .getToken()
              .then((token) => {
                res.send(token);
              })
              .catch((err) => {
                next(err);
              });
          })
          .catch((err) => {
            next(err);
          });
      });
  }

  private authByApiKey(): void {
    this.getApp()
      .route("/authenticate/apikey")
      .post((req: Request, res: Response, next: NextFunction) => {
        this.validatorService.validate(req.body, this.postAuthApiKeyPattern);
        this.apiKeyController
          .authenticateByApiKey(req)
          .then((result) => {
            res.send(result);
          })
          .catch((err) => {
            next(err);
          });
      });
  }
}
