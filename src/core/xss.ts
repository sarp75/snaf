// snaf core - modular node.js firewall
// main goal: detect/prevent xss, but extensible for other attacks
// written in ts, clean separation of core, adapters, modules

// core types for firewall modules
export interface SnafModule {
  name: string;
  enabled: boolean;

  // analyze request/response, return action (block, sanitize, allow)
  analyze(ctx: SnafContext): Promise<SnafAction> | SnafAction;
}

export interface SnafContext {
  req: any; // framework-agnostic request
  res: any; // framework-agnostic response
  // parsed data for analysis
  query?: Record<string, any>;
  body?: Record<string, any>;
  headers?: Record<string, any>;
  responseBody?: string;
  // can add more fields later
}

export type SnafAction =
  | { action: "allow" }
  | { action: "block"; reason?: string }
  | {
      action: "sanitize";
      sanitized: any;
      reason?: string;
    };

// core firewall class
export class SnafCore {
  // list of enabled modules (xss, etc)
  private modules: SnafModule[] = [];

  // add a module (xss, ssrf, etc)
  use(module: SnafModule) {
    this.modules.push(module);
  }

  // enable/disable a module by name
  setModuleEnabled(name: string, enabled: boolean) {
    const mod = this.modules.find((m) => m.name === name);
    if (mod) mod.enabled = enabled;
  }

  // main middleware/proxy handler
  async handle(ctx: SnafContext): Promise<SnafAction[]> {
    // run all enabled modules, collect actions
    const actions: SnafAction[] = [];
    for (const mod of this.modules) {
      if (!mod.enabled) continue;
      const result = await mod.analyze(ctx);
      actions.push(result);
    }
    return actions;
  }
}

// later: add default xss module, adapter helpers, etc.
