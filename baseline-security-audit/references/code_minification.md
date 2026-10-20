# Code Minification Security Analysis

Analyze the codebase to identify missing minification/uglification configurations that could expose implementation details and increase security risks:

> **Severity:** rate every finding Critical / High / Medium / Low per the Severity Scale in SKILL.md.
> **OWASP Top 10:2025:** A02 Security Misconfiguration · **ASVS 5.0:** V13 Configuration, V3 Web Frontend Security

## Core Security Principle
**All code that is sent to the user (HTML, CSS, JavaScript) should be minified in production builds. Minification itself is not a security control; what is security-relevant is source-map exposure (a publicly served `.map` file hands out the original source) and comments or debug code (`debugger;` statements, internal URLs or credentials in comments) that leak from unminified bundles.**

## 1. Angular Applications

**Check angular.json configuration:**

**First identify the builder** in `angular.json` (`projects.<name>.architect.build.builder`):

- `@angular/build:application` or `@angular-devkit/build-angular:application` (esbuild, the default since Angular 17): `optimization` defaults to `true` and `sourceMap` to `false`. `buildOptimizer` and `vendorChunk` do not exist for this builder. A production configuration that contains only `budgets` and `outputHashing` is **compliant**; do not report missing keys.
- `@angular-devkit/build-angular:browser` (webpack, legacy): the keys below apply.

```json
// Legacy webpack builder - look for production build configuration
"configurations": {
  "production": {
    "optimization": true,  // MUST be true for production
    "outputHashing": "all",
    "sourceMap": false,    // SHOULD be false for production
    "namedChunks": false,
    "extractLicenses": true,
    "vendorChunk": false,
    "buildOptimizer": true // MUST be true for production (webpack builder only)
  }
}
```

**Specific checks in angular.json:**
- A finding is an **explicit** `"optimization": false` or `"sourceMap": true` in the configuration that the pipeline deploys
- `"sourceMap": { "scripts": true, "hidden": true, "vendor": false, "sourcesContent": false }` is compliant when the `.map` files are kept server-side (error-tracking upload) and not published
- Webpack builder only: check `buildOptimizer` is `true`
- Check `defaultConfiguration` on the build target and the configuration the pipeline actually passes to `ng build`. New projects are scaffolded with `"defaultConfiguration": "production"` since Angular 12, but there is no built-in fallback: without the key, a bare `ng build` uses the base options. `ng build --configuration development` deployed = Low; `defaultConfiguration` absent while the base options enable `sourceMap` or disable `optimization` = Low, and ask the user which configuration the pipeline passes

**Files to check:** `angular.json`, build scripts in `package.json`, `webpack.config.js` / `vite.config.*` for non-Angular bundlers, the pipeline YAML for the deployed configuration, and the `dist/` output.

## 2. CSS/SCSS Minification

Angular `optimization: true` minifies styles together with the scripts. For a non-Angular bundler check its CSS minifier (`cssnano` in `postcss.config.js`, `MiniCssExtractPlugin` with `postcss-loader` in webpack, `sass --style=compressed`).

## 3. Third-Party JavaScript and CSS Files

**Third-party resources loaded from a CDN** (`<script>` / `<link>` in `index.html` without `integrity` and `crossorigin`) are rated by check 14 (security_headers.md) section 9. Here: `"subresourceIntegrity": true` in the Angular build options hashes the app's own bundles (recommendation, not a finding).

A bundler minifier that excludes `node_modules` (`new TerserPlugin({ exclude: /node_modules/ })`) ships vendor code unminified (Low). **Files to check:** `index.html`, `public/`, the build output.

## 4. Build Script Verification

A deployed build script without the production flag (`ng build --configuration development`, `webpack` without `--mode production`) or one that disables minification (`optimization: { minimize: false }`) = Low.

## 5. Server-Side Rendering (SSR) and Static Site Generation (SSG)

**`@angular/ssr`:**
- Verify both browser and server bundles are optimized
- Check the `server`, `ssr` and `prerender` options of the application builder in `angular.json`; the production configuration's `optimization` applies to both bundles

## 6. HTML Minification

Angular includes HTML minification in `optimization: true`; nothing separate to check.

## 7. Source Maps in Production

Production builds must not emit public source maps: `angular.json` `"sourceMap": false` (or the hidden form from section 1), webpack `devtool: false` or `'hidden-source-map'`, vite `build.sourcemap: false`. Maps needed for error tracking are uploaded to the tracking service and never served.

**Deployed `.map` files (executable check):** look for pipeline publish/copy steps (`CopyFiles@2`, `PublishPipelineArtifact@1`, `AzureWebApp@1`) whose `contents` include `*.map` or lack a `!**/*.map` exclusion; an IIS `web.config` without `<requestFiltering><fileExtensions><add fileExtension=".map" allowed="false" /></fileExtensions></requestFiltering>`; `//# sourceMappingURL=` comments in the deployed bundles (`grep -r "sourceMappingURL" dist/`); and a `curl -sI "$PRODUCTION_URL/<bundle>.js.map"` that returns 200. A publicly reachable `.map` is rated in section 8 (Medium).

## 8. What to Report

**For each finding, provide:**
- File path and configuration setting
- Current configuration value
- Security/performance impact
- Recommended configuration
- Build framework/tool being used

**Severity:**
- **Medium**: Source maps publicly accessible — `.map` files served from the production origin, or a `//# sourceMappingURL=` comment pointing at a reachable file (exposes source code)
- **Low**: everything else: missing or disabled minification, a development configuration deployed, `debugger;` statements and comments in production bundles (`console.log` presence on its own is not a finding), unminified third-party or vendor code, build scripts without production flags
- Not reported: suboptimal configuration with only a performance impact
