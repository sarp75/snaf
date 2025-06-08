# SNAF - Sarp's Node App Firewall

A lightweight, accurate, multi-framework XSS scanner for Node.js applications.

[![npm](https://img.shields.io/npm/v/snaf)](https://www.npmjs.com/package/snaf)
![npm](https://img.shields.io/npm/dw/snaf)
![License](https://img.shields.io/github/license/sarp75/snaf)
![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue?logo=typescript)
[![Issues](https://img.shields.io/github/issues/sarp75/snaf)](https://github.com/sarp75/snaf/issues)
[![publish to npm](https://github.com/sarp75/snaf/actions/workflows/npm-publish.yml/badge.svg)](https://github.com/sarp75/snaf/actions/workflows/npm-publish.yml)

## Sections

- [Features](#features)
- [Quick Start](#quickstart)
- [Configuration Options](#config)
- [API Reference](#api)
- [Comparison](#comparison)
- [Warnings](#warnings)

## Features <a id=“features”></a>

- **Advanced Security Testing**: Utilizes sophisticated XSS payloads from
  the [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/XSS/robot-friendly) project to ensure
  comprehensive security coverage.
- **Versatile Framework Compatibility**: Offers framework-agnostic functionality with integrated adapters for a wide
  range of frameworks.
- **Minimal Performance Impact**: Designed to maintain optimal performance with negligible overhead.
- **Extensive Customization Options**: Provides high configurability to meet specific needs and preferences.
- **Seamless Integration**: Simplifies the integration process for developers.
- **Zero Dependencies**: Operates independently without requiring any external dependencies.
- **TypeScript-Based Development**: Constructed with TypeScript for enhanced safety, while remaining compatible with
  JavaScript.

## Installation

```bash
npm install snaf
```

## Quick Start <a id="quickstart"></a>

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

### Fastify

```ts
const fastify = require("fastify")();
const { createSnaf } = require("snaf");

const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "block",
    },
  },
});

// Register SNAF as a Fastify plugin
fastify.register(snaf.fastify());

fastify.get("/", async (request, reply) => {
  return "Hello, secure world!";
});

fastify.listen({ port: 3000 });
```

### Koa

```ts
const Koa = require("koa");
const bodyParser = require("koa-bodyparser");
const { createSnaf } = require("snaf");

const app = new Koa();
app.use(bodyParser());

const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "remove",
    },
  },
});

// Add SNAF middleware
app.use(snaf.koa());

// Your normal routes
app.use(async (ctx) => {
  ctx.body = "Hello, secure world!";
});
app.listen(3000);
```

### Hono

```ts
import { Hono } from "hono";
import { createSnaf } from "snaf";

const app = new Hono();
const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "block",
    },
  },
});

// Add SNAF middleware
app.use("*", snaf.hono());

app.get("/", (c) => c.text("Hello, secure world!"));

export default app;
```

### Hapi

```ts
const Hapi = require("@hapi/hapi");
const { createSnaf } = require("snaf");

const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: "remove",
    },
  },
});

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: "localhost",
  });

  // Register SNAF as a Hapi plugin
  await server.register(snaf.hapi());

  server.route({
    method: "GET",
    path: "/",
    handler: (request, h) => {
      return "Hello, secure world!";
    },
  });

  await server.start();
  console.log("Server running on %s", server.info.uri);
};

init();
```

## Configuration Options <a id="config"></a>

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
      blockMode: "block", // 'block', 'remove', or 'report'
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

## API Reference <a id="api"></a>

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

### Comparison Graphs <a id="comparison"></a>

Here is a comparative analysis of SNAF with other widely adopted Node.js XSS protection libraries:

| Feature              | SNAF  | xss-clean | helmet | DOMPurify (Node) |
|----------------------|:-----:|:---------:|:------:|:----------------:|
| XSS Detection        |   ✅   |     ✅     |   ❌    |        ✅         |
| XSS Sanitization     |   ✅   |     ✅     |   ❌    |        ✅         |
| Block Mode           |   ✅   |     ❌     |   ❌    |        ❌         |
| Configurable         |   ✅   |    ⚠️     |   ⚠️   |        ✅         |
| Zero Dependencies?   |   ✅   |     ❌     |   ✅    |        ❌         |
| TypeScript Support   |   ✅   |    ⚠️     |   ⚠️   |        ✅         |
| Average Latency (ms) | 1.127 |   ~2.3    |  ~0.5  |      ~11.38      |
| Maintained           |   ✅   |    ⚠️     |   ⚠️   |        ⚠️        |
| Handles Evasion      |   ✅   |     ❌     |   ❌    |        ❌         |
| Granular Control     |   ✅   |     ❌     |   ❌    |        ❌         |
| Real-World Coverage  |   ✅   |    ⚠️     |   ❌    |        ⚠️        |

#### ⚠️ = Partial/limited, ✅ = Yes, ❌ = No

- **xss-clean**: No longer maintained, it overlooks sophisticated XSS vectors and provides minimal configuration
  options.
- **helmet**: Not an XSS sanitizer; it solely modifies HTTP headers, rendering your application susceptible to XSS
  payloads.
- **DOMPurify (Node)**: A resource-intensive and sluggish tool, not suited for server-side request sanitization.
  It lacks the block mode and precise control features.

### What SNAF Should Not Be Used For <a id="warnings"></a>

- **Sanitization**: SNAF is not a sanitization library. It blocks malicious requests and sanitizes them if configured to
  do so.
- **Input Validation**: SNAF is not designed for validating user input.
  Use libraries like `joi` or `express-validator` for that purpose.
- **Rate Limiting**: SNAF does not provide rate limiting features. 
  Use libraries like `express-rate-limit` for that
  purpose.
- **General Security**: SNAF is focused on XSS protection. 
 For comprehensive security, consider using it alongside other
  security measures such as HTTPS, authentication, and authorization.
- **Blind Trust**: Do not blindly trust user input or external data sources. 
Always validate and sanitize inputs as
  necessary.
  Do not solely rely on SNAF for security.

### License

MIT
