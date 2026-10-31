import { fileURLToPath } from 'node:url';
import type { Plugin } from 'esbuild';

export const reactNativeIdnaPlugin: Plugin = {
  name: 'react-native-idna',
  setup(build) {
    build.onResolve({ filter: /^\.\/idna\.js$/ }, (args) => {
      if (args.importer === fileURLToPath(new URL('../src/parser.ts', import.meta.url))) {
        return { path: fileURLToPath(new URL('../src/react-native/idna.ts', import.meta.url)) };
      }
      return undefined;
    });
  },
};
