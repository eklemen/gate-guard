#!/bin/bash -ex

npm run typecheck
npm run lint
npm run test

rm -rf dist
tsc -p .
rm -rf dist/__tests__
