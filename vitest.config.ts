import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: [
        'text',
        ['json', { file: 'coverage-final.json' }],
        ['json-summary', { file: 'coverage-summary.json' }],
      ],
    },
  },
});
