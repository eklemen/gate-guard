/* eslint-disable @typescript-eslint/no-explicit-any */
import jwt from 'jsonwebtoken';
import { NextFunction } from 'express';

import gateGuard, { UserDataRequest } from '../index';

jest.spyOn(jwt, 'verify');
jest.mock('express');

describe('gateGuard', () => {
  let req: UserDataRequest;
  let res: any;
  let next: NextFunction;
  const jwtSecret = 'shh';
  beforeEach(() => {
    next = jest.fn();
    req = {
      path: '/api/users',
      cookies: {
        token: 'mysecrettoken',
      },
    } as UserDataRequest;
    res = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
    } as any as Response;
  });
  afterEach(() => {
    jest.clearAllMocks();
  });
  test('Cookie name configuration for jwt', () => {
    delete req.cookies.token;
    req.cookies.mmmCookies = 'sometoken';
    const middleware = gateGuard({ jwtSecret, cookieName: 'mmmCookies' });
    middleware(req, res, next);
    expect(jwt.verify).toHaveBeenCalled();
  });
  describe('Whitelist config -', () => {
    test('Match basic path (no globs) /api/users', () => {
      const whitelist = ['/api/users'];
      const middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).toHaveBeenCalled();
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();
    });
    test('/api/* should whitelist /api/users', () => {
      const whitelist = ['/api/*'];
      const middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).toHaveBeenCalled();
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();
    });
    test('/api/* should NOT whitelist /api', () => {
      const whitelist = ['/api/*'];
      req.path = '/api';
      const middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).not.toHaveBeenCalled();
      expect(
        jwt.verify,
      ).toHaveBeenCalled();
    });
    test('/api/** should whitelist /api/users', () => {
      const whitelist = ['/api/**'];
      const middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).toHaveBeenCalled();
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();
    });
    test('/api/** should whitelist /api/users/2 or /api/registration/newuser', () => {
      const whitelist = ['/api/**'];
      req.path = '/api/users/2';
      let middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).toHaveBeenCalled();
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();

      req.path = '/api/users/profile';
      middleware = gateGuard({ jwtSecret, whitelist });
      middleware(req, res, next);
      expect(
        next,
      ).toHaveBeenCalled();
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();
    });
  });
  describe('JWT -', () => {
    test('jwt.verify should be called when cookies.token is present', () => {
      const middleware = gateGuard({ jwtSecret });
      middleware(req, res, next);
      expect(
        jwt.verify,
      ).toHaveBeenCalledWith(req.cookies.token, 'shh', expect.any(Function));
    });
    test('jwt.verify should NOT be called when cookies.token is NOT present', () => {
      delete req.cookies.token;
      const middleware = gateGuard({ jwtSecret });
      middleware(req, res, next);
      expect(
        jwt.verify,
      ).not.toHaveBeenCalled();
    });
    test('custom error status and message when cookies.token is NOT present', () => {
      delete req.cookies.token;
      const middleware = gateGuard({
        jwtSecret,
        missingTokenErrorStatus: 402,
        missingTokenErrorMessage: 'Did you even try to jwt?',
      });
      middleware(req, res, next);
      expect(
        res.status,
      ).toHaveBeenCalledWith(402);
      expect(
        res.send,
      ).toHaveBeenCalledWith('Did you even try to jwt?');
    });
    test('Error - jwt.verify should send status 403 by default', () => {
      const middleware = gateGuard({ jwtSecret });
      middleware(req, res, next);
      expect(
        res.status,
      ).toHaveBeenCalledWith(403);
      expect(
        res.send,
      ).toHaveBeenCalledWith('Invalid jwt.');
    });
    test('Error - jwt.verify should send custom status 499 when configured', () => {
      const middleware = gateGuard({
        jwtSecret,
        verifyTokenErrorStatus: 499,
        verifyTokenErrorMessage: 'Token is not valid.',
      });
      middleware(req, res, next);
      expect(
        res.status,
      ).toHaveBeenCalledWith(499);
      expect(
        res.send,
      ).toHaveBeenCalledWith('Token is not valid.');
    });
    test('jwt.verify should set user onto req and call next()', () => {
      const mockToken = jwt.sign({ name: 'hank hill' }, jwtSecret);
      req.cookies.token = mockToken;
      const middleware = gateGuard({
        jwtSecret,
        verifyTokenErrorStatus: 499,
        verifyTokenErrorMessage: 'Token is not valid.',
      });
      middleware(req, res, next);
      expect(
        req.user.name,
      ).toBe('hank hill');
      expect(
        next,
      ).toHaveBeenCalled();
    });
  });
});
