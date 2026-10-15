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
- Check `defaultConfiguration` (defaults to `production` since Angular 12) and the configuration the pipeline actually passes to `ng build`

**Detailed optimization configuration:**
```json
"optimization": {
  "scripts": true,     // Minify JavaScript
  "styles": true,      // Minify CSS
  "fonts": true        // Inline small fonts
}
```

**Files to check:**
- `angular.json` - Main configuration file
- Build scripts in `package.json`

## 2. CSS/SCSS Minification

**CSS preprocessor configurations:**

**PostCSS:**
```javascript
// postcss.config.js
module.exports = {
  plugins: [
    require('cssnano')({  // CSS minification
      preset: ['default', {
        discardComments: {
          removeAll: true  // Remove all comments
        }
      }]
    })
  ]
}
```

**Webpack CSS loaders:**
```javascript
// webpack.config.js
module.exports = {
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [
          MiniCssExtractPlugin.loader,
          'css-loader',
          'postcss-loader'  // For minification
        ]
      },
      {
        test: /\.scss$/,
        use: [
          MiniCssExtractPlugin.loader,
          'css-loader',
          'postcss-loader',
          'sass-loader'
        ]
      }
    ]
  },
  plugins: [
    new MiniCssExtractPlugin({
      filename: '[name].[contenthash].css'
    })
  ]
}
```

**SASS/SCSS build configurations:**
```json
// package.json
"scripts": {
  "build:css": "sass --style=compressed src/styles:dist/styles"
}
```

## 3. Third-Party JavaScript and CSS Files

**Critical checks for third-party resources:**

**Verify use of minified versions:**
```html
<!-- BAD - Development version -->
<script src="https://cdn.example.com/library.js"></script>
<link href="https://cdn.example.com/styles.css" rel="stylesheet">

<!-- GOOD - Minified version -->
<script src="https://cdn.example.com/library.min.js"></script>
<link href="https://cdn.example.com/styles.min.css" rel="stylesheet">
```

**Check package.json dependencies:**
- Verify production builds use minified versions from CDNs
- Check if build process includes third-party files in bundling
- Ensure third-party files are processed by build optimization

**Bundled third-party libraries:**
```javascript
// Verify third-party code is included in bundle optimization
// Check node_modules processing in webpack/vite config
module.exports = {
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        exclude: /node_modules/  // RED FLAG - excludes libraries
      })
    ]
  }
}

// CORRECT - includes all code
module.exports = {
  optimization: {
    minimize: true,
    minimizer: [new TerserPlugin()]
  }
}
```

**Files to check:**
- `index.html` - CDN script/style references
- `public/` folder - Static third-party files
- Build output directory - Verify files are minified

## 4. Build Script Verification

**Check package.json build scripts:**

```json
{
  "scripts": {
    "build": "ng build --configuration production",  // Angular
    "build": "vite build",                            // Vite
    "build": "webpack --mode production"              // Webpack
  }
}
```

**Flags to raise:**
- Build scripts missing production flags
- Development builds being deployed
- Missing or incorrect build configurations
- Build scripts that explicitly disable minification

## 5. Server-Side Rendering (SSR) and Static Site Generation (SSG)

**`@angular/ssr`:**
- Verify both browser and server bundles are optimized
- Check the `server`, `ssr` and `prerender` options of the application builder in `angular.json`; the production configuration's `optimization` applies to both bundles

## 6. HTML Minification

**Check for HTML minification in build process:**

**Angular:**
- HTML minification is included in `optimization: true`

## 7. Source Maps in Production

**Critical security check - source maps expose source code:**

```javascript
// webpack.config.js
module.exports = {
  devtool: false  // MUST be false or undefined for production
  // OR
  devtool: 'hidden-source-map'  // Only if source maps needed for error tracking
}

// angular.json
"sourceMap": false  // MUST be false for production

// vite.config.js
export default defineConfig({
  build: {
    sourcemap: false  // MUST be false for production
  }
})
```

**If source maps are needed for error tracking:**
- Use `hidden-source-map` to keep maps separate
- Upload source maps to error tracking service (Sentry, etc.)
- Do NOT serve source maps publicly
- Store source maps securely on the server only

## 8. What to Report

**Report ALL instances of (Medium for publicly served source maps, Low for everything else):**
- Missing or disabled minification in production builds
- `optimization: false` in production configurations
- Source maps enabled in production builds
- Development versions of third-party libraries in production
- Build scripts without production flags
- Unminified CSS/SCSS in production output
- Unminified JavaScript/TypeScript in production output
- HTML files without minification
- Third-party files excluded from build optimization
- `debugger;` statements and comments in production bundles (`console.log` presence on its own is not a finding)

**For each finding, provide:**
- File path and configuration setting
- Current configuration value
- Security/performance impact
- Recommended configuration
- Build framework/tool being used

**Severity:**
- **Medium**: Source maps publicly accessible — `.map` files served from the production origin, or a `//# sourceMappingURL=` comment pointing at a reachable file (exposes source code)
- **Low**: everything else in the list above (missing minification, `debugger;` statements, comments, development versions of third-party libraries, build scripts without production flags)
- Not reported: suboptimal configuration with only a performance impact

## 9. Files and Directories to Check

**Configuration files:**
- `angular.json` - Angular projects
- `webpack.config.js` - Webpack configurations
- `vite.config.js` / `vite.config.ts` - Vite projects
- `postcss.config.js` - CSS processing
- `package.json` - Build scripts
- `.env.production` - Production environment variables

**Build output directories to verify:**
- `dist/` - Common build output
- `public/` - Static files (check for unminified third-party files)

## 10. Verification Steps

**Manual verification of production build:**

1. **Run production build:**
   ```bash
   npm run build
   # or
   ng build --configuration production
   ```

2. **Inspect output files:**
   - Check file sizes (minified files are significantly smaller)
   - Open files and verify they are minified (no whitespace, short variable names)
   - Verify no source maps are present (`.map` files)

3. **Check for comments and debugging:**
   - Check for `debugger;` statements (a finding; `console.log` presence on its own is not)
   - Look for code comments

4. **Verify third-party libraries:**
   - Check if using `.min.js` versions
   - Verify third-party code is included in bundle optimization

## 11. Best Practices

**Verify that the application:**
- Has separate development and production build configurations
- Minifies all JavaScript/TypeScript code in production
- Minifies all CSS/SCSS code in production
- Minifies HTML templates in production
- Disables source maps in production (or uses hidden source maps)
- Uses minified versions of third-party libraries
- Removes `debugger;` statements
- Removes comments from production code
- Uses content hashing for cache busting
- Optimizes images and other assets
- Uses tree-shaking to remove unused code
- Implements code splitting for better performance

**Security benefits of minification:**
- Makes reverse engineering more difficult
- Removes comments that may contain sensitive information
- Obscures variable and function names
- Removes `debugger;` statements and debug-only code
- Reduces file size and improves performance
- Provides security through obscurity (not primary defense, but helpful)

**Important note:**
- Minification is NOT a security feature, it's security through obscurity
- Never rely on minification alone to protect sensitive logic
- Always implement proper server-side security controls
- Keep sensitive logic and secrets on the server side
- Use minification as one layer of defense-in-depth

## 12. Common Misconfigurations

**Watch out for:**

```javascript
// WRONG - Minification explicitly disabled
optimization: { minimize: false }

// WRONG - Development build deployed to production
ng build --configuration development
// NOTE: a bare `ng build` has used the production configuration by default since Angular 12 and is NOT a finding

// WRONG - Source maps in production
devtool: 'source-map'

// CORRECT - No source maps in production
devtool: false
```

**Environment-specific builds:**
```json
// Verify environment variables
{
  "scripts": {
    "build:dev": "ng build --configuration development",
    "build:prod": "ng build --configuration production",
    "build": "ng build"  // production by default since Angular 12
  }
}
```

