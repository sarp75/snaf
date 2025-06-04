# SNAF - Sarp's Node App Firewall

A lightweight, accurate, multi-framework XSS scanner for Node.js applications.

[![npm](https://img.shields.io/npm/v/snaf)](https://www.npmjs.com/package/snaf)
![npm](https://img.shields.io/npm/dw/snaf)
![License](https://img.shields.io/github/license/sarp75/snaf)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?logo=typescript)
[![Issues](https://img.shields.io/github/issues/sarp75/snaf)](https://github.com/sarp75/snaf/issues)
[![Last Commit](https://img.shields.io/github/last-commit/sarp75/snaf)](https://github.com/sarp75/snaf/commit/main)

## Features

- Robust XSS protection
- Framework-agnostic with built-in adapters for many frameworks
- Almost no performance impact
- Highly configurable
- Easy to integrate
- No dependencies at all
- Built with TypeScript for extra safety _(still works with JavaScript)_

## Installation

```bash
npm install snaf
```

## Quick Start

### Express.js

```ts
const express = require("express");
const { createSnaf } = require("snaf");

const app = express();
const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "sanitize",
    },
  },
});

// Add SNAF middleware
app.use(snaf.express());

// Your normal routes
app.get("/", (req, res) => {
  res.send("Hello, secure world!");
});

app.listen(3000);
```

### Next.js

```ts
// pages/api/_middleware.js for Next.js 12
// middleware.ts for Next.js 13+
import { createSnaf } from "snaf";

const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "block",
    },
  },
});

export default snaf.nextjs()(async function handler() {
  /* your normal middleware here, or just leave empty */
});
```

## Configuration Options

```ts
const snaf = createSnaf({
  // Global settings
  enabled: true,

  // Module-specific settings
  modules: {
    xss: {
      enabled: true, // enable the module
      inlineEventHandlers: true, // <svg onload="alert('1')">
      dynamicContent: true, // <script>alert('1')</script>
      urlParameters: true, // search?q=alert('1')
      formInputs: true, // <input value="alert('1')">
      userGeneratedContent: true, // <textarea>user input</textarea>
      blockMode: "sanitize", // 'block', 'sanitize', 'remove', or 'report'
      sensitiveParams: ["token", "password"], // sensitive url parameters
      whitelistedDomains: ["trusted-domain.com"], // trust this domain blindly
      whitelistedPaths: ["/images/"], // allow specific paths
    },
  },

  // Action behavior settings
  onBlock: (reason) => console.log(`Blocked request: ${reason}`),
  onSanitize: (reason, original, sanitized) =>
    console.log(`Sanitized malicious content: ${reason}`),
});
```

## API Reference

### `createSnaf(config)`

Create a new SNAF instance with the provided configuration.

### `snaf.express()`

Returns an Express.js middleware function.

### `snaf.nextjs()`

Returns a Next.js middleware function.

### `snaf.enable(enabled)`

Enable or disable the firewall.

### `snaf.enableModule(name, enabled)`

Enable or disable a specific module, specified by name.

### `snaf.use(module)`

Add a custom module.

### License

MIT
