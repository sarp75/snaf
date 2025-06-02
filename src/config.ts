// config system for snaf
// allows users to customize firewall behavior

export interface SnafConfig {
  // global settings
  enabled: boolean;

  // module-specific settings
  modules: {
    xss?: XssModuleConfig;
    // other modules can be added here later (ssrf, sqli, etc.)
  };

  // action behavior settings
  onBlock?: (reason?: string) => any;
  onSanitize?: (reason?: string, original?: any, sanitized?: any) => any;
}

export interface XssModuleConfig {
  // Module state
  // Pro tip: if you set this shit to false, uninstall snaf
  enabled?: boolean;

  // Detection vectors
  // !!!inline event handlers (e.g., onclick, onmouseover)
  inlineEventHandlers?: boolean;

  // !!!dynamically generated content (e.g., <script> tags, innerHTML)
  dynamicContent?: boolean;

  // !!url parameters
  urlParameters?: boolean;

  // !!form inputs
  formInputs?: boolean;

  // !other user-generated content
  userGeneratedContent?: boolean;

  // Action modes
  // block - block the request with a 403 Forbidden response
  // sanitize - remove the malicious content and continue processing
  // remove - remove the malicious block and continue processing
  // report - only report the XSS detection without blocking
  blockMode?: "block" | "sanitize" | "remove" | "report";

  // Advanced configuration options
  sensitiveParams?: string[]; // parameters to apply stricter validation to
  whitelistedDomains?: string[]; // domains to whitelist from XSS checks
  whitelistedPaths?: string[]; // paths to whitelist from XSS checks
  customPayloads?: string[]; // additional regex patterns to detect
}

// default configuration
export const defaultConfig: SnafConfig = {
  enabled: true,
  modules: {
    xss: {
      enabled: true,
      inlineEventHandlers: true,
      dynamicContent: true,
      urlParameters: true,
      formInputs: true,
      userGeneratedContent: true,
      blockMode: "block",
    },
  },
};

// merge user config with defaults
export function createConfig(userConfig: Partial<SnafConfig> = {}): SnafConfig {
  return {
    ...defaultConfig,
    ...userConfig,
    modules: {
      ...defaultConfig.modules,
      ...userConfig.modules,
      // deep merge module configs
      xss: userConfig.modules?.xss
        ? { ...defaultConfig.modules.xss, ...userConfig.modules.xss }
        : defaultConfig.modules.xss,
    },
  };
}
