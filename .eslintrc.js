'use strict';

module.exports = {
  root: true,
  extends: ['@mongodb-js/eslint-config-devtools'],
  parserOptions: {
    tsconfigRootDir: __dirname,
    project: ['./tsconfig.json'],
  },
  overrides: [
    {
      files: ['test.js', 'test/**/*.js'],
      env: { mocha: true },
    },
  ],
  rules: {
    // This is a build tool, progress and diagnostics are meant for the terminal.
    'no-console': 'off',
  },
};
