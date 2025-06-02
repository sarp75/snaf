# SNAF - Sarp's Node App Firewall

A lightweight, accurate, multi-framework XSS scanner for Node.js applications.

## Features

- 🔒 Robust XSS protection
- 🔄 Framework-agnostic with built-in adapters for many frameworks
- 🚀 Low performance impact
- ⚙️ Highly configurable
- 📦 Easy to integrate

## Installation

```bash
npm install snaf
# or
yarn add snaf
# or
pnpm add snaf
```

## Quick Start

### Express.js

```javascript
const express = require('express');
const { createSnaf } = require('snaf');

const app = express();
const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: 'sanitize'
    }
  }
});

// Add SNAF middleware
app.use(snaf.express());

app.get('/', (req, res) => {
  res.send('Hello, secure world!');
});

app.listen(3000);
```

### Next.js

```javascript
// pages/api/_middleware.js (for Next.js 12)
// or
// middleware.ts (for Next.js 13+)
import { createSnaf } from 'snaf';

const snaf = createSnaf({
  modules: {
    xss: {
      enabled: true,
      blockMode: 'sanitize'
    }
  }
});

// Add your Next.js specific implementation here
// This will be expanded in future versions

export default function middleware(req, res) {
  // Apply SNAF protection
  return snaf.nextjs()(req, res);
}
```

## Configuration Options

```javascript
const snaf = createSnaf({
  // Global settings
  enabled: true,
  
  // Module-specific settings
  modules: {
    xss: {
      enabled: true,
      inlineEventHandlers: true,
      dynamicContent: true,
      urlParameters: true,
      formInputs: true,
      userGeneratedContent: true,
      blockMode: 'sanitize', // 'block', 'sanitize', 'remove', or 'report'
      sensitiveParams: ['token', 'password'],
      whitelistedDomains: ['trusted-domain.com'],
      whitelistedPaths: ['/public/']
    }
  },
  
  // Action behavior settings
  onBlock: (reason) => console.log(`Blocked request: ${reason}`),
  onSanitize: (reason, original, sanitized) => console.log(`Sanitized content: ${reason}`)
});
```

## API Reference

### `createSnaf(config)`

Creates a new SNAF instance with the provided configuration.

### `snaf.express()`

Returns an Express.js middleware function.

### `snaf.enable(enabled)`

Enable or disable the firewall.

### `snaf.enableModule(name, enabled)`

Enable or disable a specific module.

### `snaf.use(module)`

Add a custom module to SNAF.

## License

MIT
