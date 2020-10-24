# gate-guard

Lightweight and configurable ExpressJS middleware to decode and verify [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) JWTs that are sent via cookies.

Let the gate-guard protect your resources by deciding what calls make it through or not.

## Installation
```shell script
npm i --save gate-guard
# or 
yarn add gate-guard
```

## Minimum Setup

This example will protect all routes listed after the middleware behind the jwt verification. 

```javascript
import gateGuard from 'gate-guard';

// jwtSecret must match the secret used to sign the jwt 
app.use(gateGuard({ jwtSecret: 'shh' }))

// Routes here
```

## Configurations
| Option  | Default Value  | Required  |  Description |
|---|---|---|---|
|  `jwtSecret` |  `undefined` | Yes  |  The secret/cert that was used to sign/encode the JWT |
|  `whitelist` |  `[]` | Optional  |  Allow certain endpoints or endpoint groups to bypass jwt checking. Example registration, login, forgot password. Simply calls `next()` if `req.path` is whitelisted. Supports globbing patterns via picomatch. |
| `missingTokenErrorStatus`  | `401`  | Optional  | HTTP status returned when the key for the jwt is missing from `cookies`.  |
|  `missingTokenErrorMessage` | 'Missing token.'  | Optional  | Message to show when there is no cookie containing the JWT present at all.  |
|  `verifyTokenErrorStatus` |  `403` |  Optional |  HTTP status returned when the provided JWT failed to verify. |
|  `verifyTokenErrorMessage` |  'Invalid jwt.' |  Optional |  HTTP Message returned when the provided JWT failed to verify. |
| `cookieName`  | `'token'`  |  Optional | The key where the JWT can be found within the `req.cookies` object. |

## Examples

#### Basic whitelist usage
```javascript
app.use(gateGuard({
  jwtSecret,
  whitelist: [
    '/api/registration/verify',
    '/api/registration/create/account',
    '/api/registration/create/profile',
  ]
}));
```
#### Whitelist multiple routes with globs
Supports globbing via the [picomatch](https://github.com/micromatch/picomatch) library
```javascript
// The same example above can be written as
app.use(gateGuard({
  jwtSecret,
  whitelist: ['/api/registration/**']
}));

// All common glob patterns supported
app.use(gateGuard({
  jwtSecret,
  whitelist: [
    '/api/*/create/account',
    '/api/**/profile/*',
  ]
}));

// Note on matching
app.use(gateGuard({
  jwtSecret,
  // This will whitelist any sub-routes of /api/registration/
  // But the base route /api/registration itself will not be whitelisted
  whitelist: ['/api/registration/**']
}));
```


