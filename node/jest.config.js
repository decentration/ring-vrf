module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    transform: {
      '^.+\\.ts$': 'ts-jest',
    },
    transformIgnorePatterns: [
      'node_modules/(?!node-fetch)',
    ],
    extensionsToTreatAsEsm: ['.ts'],
      moduleNameMapper: {
      '^@noble/hashes/(.*)$': '<rootDir>/node_modules/@noble/hashes/sha256.js',
    },
  };