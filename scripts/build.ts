import { execSync } from 'node:child_process';
import { chmodSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { build as esbuild } from 'esbuild';
import pkg from '../package.json' with { type: 'json' };

async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true });
}

function createDistPackageJson() {
  // Create a simplified package.json for distribution
  const distPkg: Record<string, unknown> = {
    name: pkg.name,
    version: pkg.version,
    type: 'module',
    'react-native': './cjs/index.cjs',
    main: './cjs/index.cjs',
    module: './esm/index.js',
    browser: './browser/index.js',
    types: './types/index.d.ts',
    bin: {
      didwebvh: './cli/didwebvh.js',
    },
    files: ['cjs', 'esm', 'browser', 'cli', 'types'],
    exports: {
      '.': {
        'react-native': './cjs/index.cjs',
        browser: './browser/index.js',
        import: './esm/index.js',
        require: './cjs/index.cjs',
        types: './types/index.d.ts',
      },
      './types': {
        types: './types/types.d.ts',
      },
    },
    dependencies: pkg.dependencies,
  };

  // Only add optional fields if they exist in the source package.json
  if ('description' in pkg) distPkg.description = (pkg as Record<string, unknown>).description;
  if ('author' in pkg) distPkg.author = (pkg as Record<string, unknown>).author;
  if ('license' in pkg) distPkg.license = pkg.license;
  if ('repository' in pkg) distPkg.repository = pkg.repository;
  if ('bugs' in pkg) distPkg.bugs = (pkg as Record<string, unknown>).bugs;
  if ('homepage' in pkg) distPkg.homepage = (pkg as Record<string, unknown>).homepage;

  writeFileSync('./dist/package.json', JSON.stringify(distPkg, null, 2));
}

function createDistReadme() {
  // Read the main README
  const readme = readFileSync('./README.md', 'utf-8');

  // Add distribution-specific information
  const distReadme = `# ${pkg.name}

${readme}

## Distribution Package Structure

This package includes:
- \`node/\` - Node.js ESM bundle
- \`browser/\` - Browser ESM bundle
- \`cli/\` - Command-line interface
- \`types/\` - TypeScript type declarations
`;

  writeFileSync('./dist/README.md', distReadme);
}

async function build() {
  // Clean dist directory first
  execSync('rm -rf dist');

  // Create output directories
  console.log('\nCreating output directories...');
  await Promise.all([
    ensureDir('./dist/cjs'),
    ensureDir('./dist/esm'),
    ensureDir('./dist/browser'),
    ensureDir('./dist/cli'),
    ensureDir('./dist/types'),
  ]);

  // Build ESM for Node.js
  console.log('\nBuilding ESM bundle...');
  await esbuild({
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'esm',
    platform: 'node',
    outfile: 'dist/esm/index.js',
    sourcemap: true,
  });

  // Build CJS for Node.js
  console.log('\nBuilding CJS bundle...');
  await esbuild({
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'cjs',
    platform: 'node',
    outfile: 'dist/cjs/index.cjs',
    sourcemap: true,
  });

  // Build for Browser
  console.log('\nBuilding Browser bundle...');
  await esbuild({
    entryPoints: ['src/index.ts'],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    outfile: 'dist/browser/index.js',
    sourcemap: true,
    minify: true,
    define: {
      'process.env.NODE_ENV': '"production"',
      global: 'globalThis',
    },
  });

  // Build CLI
  console.log('\nBuilding CLI...');
  await esbuild({
    entryPoints: ['src/cli/index.ts'],
    bundle: true,
    format: 'esm',
    platform: 'node',
    outfile: 'dist/cli/didwebvh.js',
    sourcemap: true,
  });

  // Generate type declarations
  console.log('\nGenerating TypeScript declarations...');

  // Create a temporary tsconfig for declarations
  const declarationConfig = {
    compilerOptions: {
      declaration: true,
      emitDeclarationOnly: true,
      declarationDir: './dist/types',
      moduleResolution: 'bundler',
      module: 'esnext',
      target: 'esnext',
      allowSyntheticDefaultImports: true,
      skipLibCheck: true,
      rootDir: './src',
      types: ['node'],
    },
    include: ['src/**/*'],
    exclude: ['node_modules', 'dist', 'test'],
  };

  writeFileSync('tsconfig.declarations.json', JSON.stringify(declarationConfig, null, 2));

  try {
    execSync('tsc --project tsconfig.declarations.json', { stdio: 'inherit' });
  } finally {
    execSync('rm -f tsconfig.declarations.json');
  }

  // Make CLI executable
  chmodSync('dist/cli/didwebvh.js', 0o755);

  // Create distribution package.json and README
  console.log('\nCreating distribution package files...');
  createDistPackageJson();
  createDistReadme();

  // Verify output directories exist and have content
  const dirs = ['cjs', 'esm', 'browser', 'cli', 'types'].map((dir) => `dist/${dir}`);
  for (const dir of dirs) {
    if (!existsSync(dir)) {
      console.error(`Missing output directory: ${dir}`);
      process.exit(1);
    }
    const files = readdirSync(dir);
    if (files.length === 0) {
      console.error(`No files in output directory: ${dir}`);
      process.exit(1);
    }
    console.log(`\nFiles in ${dir}:`, files);
  }

  console.log('\nBuild completed successfully!');
}

await build();
