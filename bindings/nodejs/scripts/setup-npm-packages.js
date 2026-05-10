#!/usr/bin/env node
/**
 * Generate platform-specific npm packages for sensor
 */

const fs = require("fs");
const path = require("path");

const VERSION = "1.4.0";

const PLATFORMS = [
  { name: "linux-x64", os: "linux", cpu: "x64", libName: "libsensor-linux-amd64.so" },
  { name: "linux-arm64", os: "linux", cpu: "arm64", libName: "libsensor-linux-arm64.so" },
  { name: "darwin-x64", os: "darwin", cpu: "x64", libName: "libsensor-darwin-amd64.dylib" },
  { name: "darwin-arm64", os: "darwin", cpu: "arm64", libName: "libsensor-darwin-arm64.dylib" },
  { name: "win32-x64", os: "win32", cpu: "x64", libName: "libsensor-windows-amd64.dll" },
];

const npmDir = path.join(__dirname, "..", "npm");

for (const platform of PLATFORMS) {
  const pkgDir = path.join(npmDir, platform.name);

  fs.mkdirSync(pkgDir, { recursive: true });

  const packageJson = {
    name: `@sensor/${platform.name}`,
    version: VERSION,
    description: `HTTPCloak native binary for ${platform.os} ${platform.cpu}`,
    os: [platform.os],
    cpu: [platform.cpu],
    main: "lib.js",
    license: "MIT",
    repository: {
      type: "git",
      url: "https://github.com/jesterfoidchopped/akamai-v3-sensor",
    },
    publishConfig: {
      access: "public",
    },
  };

  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify(packageJson, null, 2) + "\n"
  );

  const libJs = `// Auto-generated - exports path to native library
const path = require("path");
module.exports = path.join(__dirname, "${platform.libName}");
`;
  fs.writeFileSync(path.join(pkgDir, "lib.js"), libJs);

  console.log(`Created: @sensor/${platform.name}`);
}

const optionalDeps = {};
for (const platform of PLATFORMS) {
  optionalDeps[`@sensor/${platform.name}`] = VERSION;
}

console.log("\nAdd to main package.json optionalDependencies:");
console.log(JSON.stringify(optionalDeps, null, 2));
