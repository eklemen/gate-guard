// eslint-disable-next-line import/no-extraneous-dependencies
import { Request, Response, NextFunction } from 'express';
import { verify, VerifyOptions, JsonWebTokenError } from 'jsonwebtoken';
import pm from 'picomatch';

export interface Configs {
  jwtSecret: string;
  whitelist?: string[];
  missingTokenErrorStatus?: number;
  missingTokenErrorMessage?: string;
  verifyTokenErrorStatus?: number;
  verifyTokenErrorMessage?: string;
  cookieName?: string;
  jwtVerifyOptions?: VerifyOptions;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type DecodedToken = { [key: string]: any };

export interface UserDataRequest extends Request {
  user: DecodedToken;
}

const gateGuard = (
  {
    jwtSecret,
    whitelist = [],
    missingTokenErrorStatus = 401,
    missingTokenErrorMessage = 'Missing token.',
    verifyTokenErrorStatus = 403,
    verifyTokenErrorMessage = 'Invalid jwt.',
    cookieName = 'token',
    jwtVerifyOptions = {},
  }: Configs,
) => (
  req: UserDataRequest,
  res: Response,
  next: NextFunction,
) => {
  let isMatch = false;
  for (let i = 0; i < whitelist.length; i++) {
    if (pm(whitelist[i])(req.path)) isMatch = true;
  }
  if (isMatch) {
    next();
  } else {
    const token = req.cookies[cookieName];
    if (!token) {
      return res
        .status(missingTokenErrorStatus)
        .send(missingTokenErrorMessage);
    }
    verify(
      token,
      jwtSecret,
      jwtVerifyOptions,
      (err: JsonWebTokenError, data: DecodedToken) => {
        if (err) {
          return res
            .status(verifyTokenErrorStatus)
            .send(verifyTokenErrorMessage);
        }
        req.user = data;
        next();
      },
    );
  }
};
export default gateGuard;
