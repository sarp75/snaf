// snaf main entry point
// provides an easy-to-use api for setting up the firewall

// mit license idk
import {SnafCore} from "./core/xss";
import {createConfig, SnafConfig} from "./config";
import {createExpressMiddleware} from "./adapters/express";
import {createNextMiddleware} from "./adapters/next";

import {XssModule} from "./modules/xss";
import {createFastifyPlugin} from "./adapters/fastify";
import {createKoaMiddleware} from "./adapters/koa";
import {createHonoMiddleware} from "./adapters/hono";
import {createHapiPlugin} from "./adapters/hapi";

// noinspection JSUnusedGlobalSymbols
export class Snaf {
  private readonly core: SnafCore;
  private readonly config: SnafConfig;

  constructor(userConfig: Partial<SnafConfig> = {}) {
    // initialize core firewall
    this.core = new SnafCore();

    // merge user config with defaults
    this.config = createConfig(userConfig);

    // auto-register default modules based on config
    this.registerDefaultModules();
  }

  // allow users to add custom modules
  use(module: any) {
    this.core.use(module);
    return this;
  }

  // adapter for express.js
  express() {
    return createExpressMiddleware(this.core, this.config);
  }

  // enable/disable the entire firewall
  enable(enabled: boolean = true) {
    this.config.enabled = enabled;
    return this;
  }

  nextjs() {
    return createNextMiddleware(this.core, this.config);
  }

  fastify() {
    return createFastifyPlugin(this.core, this.config);
  }

  koa() {
    return createKoaMiddleware(this.core, this.config);
  }

  hono() {
    return createHonoMiddleware(this.core, this.config);
  }

  hapi() {
    return createHapiPlugin(this.core, this.config);
  }

  // no adonis() {} as it creates conflicts

  // enable/disable specific module
  enableModule(name: string, enabled: boolean = true) {
    this.core.setModuleEnabled(name, enabled);
    return this;
  }

  // access the core for advanced usage
  getCore() {
    return this.core;
  }
  // register built-in security modules based on config
  private registerDefaultModules() {
    // register xss module if enabled in config
    if (this.config.modules.xss ?? false) {
      // @ts-expect-error fuck you eslint
      this.core.use(new XssModule(this.config.modules.xss));
    }

    // other modules can be registered here in the future
  }
}

// convenient factory function
export function createSnaf(config?: Partial<SnafConfig>) {
  return new Snaf(config);
}

// export everything needed by users
export * from "./core/xss";
export * from "./config";
export { createExpressMiddleware } from "./adapters/express";

// default export for easy importing
export default createSnaf;
