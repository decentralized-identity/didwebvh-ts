import { BuildConfig } from "bun";
import pkg from "../package.json";
import { existsSync, readdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { mkdir } from "node:fs/promises";

// Base externals list
const baseExternals = [
  ...Object.keys(pkg.dependencies || {})
];

// Library builds
const browserConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  minify: true,
  sourcemap: "external",
  external: baseExternals,
  target: "browser",
  format: "esm",
  outdir: "./dist/browser",
  define: {
    'process.env.NODE_ENV': '"production"',
    'global': 'window',
  },
};

const esmConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  minify: false,
  sourcemap: "external",
  external: baseExternals,
  target: "node",
  format: "esm",
  outdir: "./dist/esm",
};

const dynamicImportToCjsPlugin = {
  name: 'dynamic-import-to-cjs',
  setup(build: any) {
    build.onLoad({ filter: /\.[jt]s$/ }, async (args: any) => {
      const contents = await Bun.file(args.path).text();
      // Replace dynamic imports with requires
      const transformed = contents.replace(
        /await\s+import\((.*?)\)/g, 
        'require($1)'
      );
      return { contents: transformed };
    });
  }
};

const cjsConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  minify: false,
  sourcemap: "external",
  external: baseExternals,
  target: "node",
  format: "cjs",
  outdir: "./dist/cjs",
  loader: {
    '.js': 'js'
  },
  plugins: [
    dynamicImportToCjsPlugin
  ]
};

const cliConfig: BuildConfig = {
  entrypoints: ["./src/cli.ts"],
  minify: false,
  sourcemap: "external",
  external: baseExternals,
  target: "node",
  format: "esm",
  outdir: "./dist/cli",
  naming: {
    entry: "didwebvh.js"
  }
};

async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true });
}

function createDistPackageJson() {
  // Create a simplified package.json for distribution
  const distPkg: any = {
    name: pkg.name,
    version: pkg.version,
    type: "module",
    main: "./cjs/index.cjs",
    module: "./esm/index.js",
    browser: "./browser/index.js",
    types: "./types/index.d.ts",
    bin: {
      "didwebvh": "./cli/didwebvh.js"
    },
    files: [
      "cjs",
      "esm", 
      "browser",
      "cli",
      "types"
    ],
    exports: {
      ".": {
        "browser": "./browser/index.js",
        "import": "./esm/index.js",
        "require": "./cjs/index.cjs",
        "types": "./types/index.d.ts"
      }
    },
    dependencies: pkg.dependencies
  };

  // Only add optional fields if they exist in the source package.json
  if ('description' in pkg) distPkg.description = pkg.description;
  if ('author' in pkg) distPkg.author = pkg.author;
  if ('license' in pkg) distPkg.license = pkg.license;
  if ('repository' in pkg) distPkg.repository = pkg.repository;
  if ('bugs' in pkg) distPkg.bugs = pkg.bugs;
  if ('homepage' in pkg) distPkg.homepage = pkg.homepage;

  writeFileSync("./dist/package.json", JSON.stringify(distPkg, null, 2));
}

function createDistReadme() {
  // Read the main README
  const readme = readFileSync("./README.md", "utf-8");
  
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

  writeFileSync("./dist/README.md", distReadme);
}

async function renameCjsFiles() {
  const cjsDir = "./dist/cjs";
  const files = readdirSync(cjsDir);
  
  await Promise.all(
    files
      .filter(file => file.endsWith('.js'))
      .map(file => renameSync(
        `${cjsDir}/${file}`,
        `${cjsDir}/${file.replace('.js', '.cjs')}`
      ))
  );
}

async function build() {
  console.log("External packages:", baseExternals);
  
  // Clean dist directory first
  await Bun.spawn(["rm", "-rf", "dist"], {
    stdout: "inherit",
    stderr: "inherit",
  }).exited;
  
  // Create output directories
  console.log("\nCreating output directories...");
  await Promise.all([
    ensureDir("./dist/cjs"),
    ensureDir("./dist/esm"),
    ensureDir("./dist/browser"),
    ensureDir("./dist/cli"),
    ensureDir("./dist/types")
  ]);

  // Build ESM for Node.js
  console.log("\nBuilding ESM bundle...");
  const esmResult = await Bun.build(esmConfig);
  if (!esmResult.success) {
    console.error("ESM build failed:", esmResult.logs);
    process.exit(1);
  }

  // Build CJS for Node.js
  console.log("\nBuilding CJS bundle...");
  const cjsResult = await Bun.build(cjsConfig);
  if (!cjsResult.success) {
    console.error("CJS build failed:", cjsResult.logs);
    process.exit(1);
  }

  // Rename CJS files to .cjs
  console.log("\nRenaming CJS files...");
  await renameCjsFiles();

  // Build for Browser
  console.log("\nBuilding Browser bundle...");
  const browserResult = await Bun.build(browserConfig);
  if (!browserResult.success) {
    console.error("Browser build failed:", browserResult.logs);
    process.exit(1);
  }

  // Build CLI
  console.log("\nBuilding CLI...");
  const cliResult = await Bun.build(cliConfig);
  if (!cliResult.success) {
    console.error("CLI build failed:", cliResult.logs);
    process.exit(1);
  }

  // Generate type declarations
  console.log("\nGenerating TypeScript declarations...");
  
  // Create a temporary tsconfig for declarations
  const declarationConfig = {
    compilerOptions: {
      declaration: true,
      emitDeclarationOnly: true,
      declarationDir: "./dist/types",
      moduleResolution: "bundler",
      module: "esnext",
      target: "esnext",
      allowSyntheticDefaultImports: true,
      esModuleInterop: true,
      skipLibCheck: true,
      rootDir: "./src",
    },
    include: ["src/**/*"],
    exclude: ["node_modules", "dist", "test"]
  };

  writeFileSync("tsconfig.declarations.json", JSON.stringify(declarationConfig, null, 2));

  const tscResult = await Bun.spawn([
    "tsc",
    "--project", "tsconfig.declarations.json",
  ], {
    stdout: "inherit",
    stderr: "inherit",
  }).exited;
  
  // Clean up temporary config
  await Bun.spawn(["rm", "tsconfig.declarations.json"]);
  
  if (tscResult !== 0) {
    console.error("TypeScript compilation failed");
    process.exit(1);
  }

  // Make CLI executable
  const proc2 = Bun.spawn(["chmod", "+x", "dist/cli/didwebvh.js"], {
    stdout: "inherit",
    stderr: "inherit",
  });
  await proc2.exited;

  // Create distribution package.json and README
  console.log("\nCreating distribution package files...");
  createDistPackageJson();
  createDistReadme();

  // Verify output directories exist and have content
  const dirs = ['cjs', 'esm', 'browser', 'cli', 'types'].map(dir => `dist/${dir}`);
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

  console.log("\nBuild completed successfully!");
}

await build(); 