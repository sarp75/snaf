import { SnafAction, SnafContext, SnafModule } from "../core/xss";
import { XssModuleConfig } from "../config";

// A big fucking hole coming right up to termux kiddos
interface XssDetectionResult {
  detected: boolean;
  count: number;
  vectors: string[];
  contexts: Set<string>;
  severity: "low" | "medium" | "high" | "critical";
  sanitizedFields: Record<string, { original: string; sanitized: string }>;
}

// Extended regex patterns organized by context and attack type
const XSS_PATTERNS = {
  // HTML context patterns
  html: {
    scriptTags: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    dangerousTags:
      /<(iframe|object|embed|form|applet|meta|base|link)\b[^>]*>/gi,
    dangerousAttributes:
      /\b(href|src|style|lowsrc|ping|formaction|action|data|codebase|dynsrc|formmethod|rel)\s*=\s*(['"`])(?!https?:\/\/|\/\/|\/|#|mailto:|tel:|about:|data:image).*?\2/gi,
    svgEvents:
      /<svg\b[^>]*>(?:<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|<\/svg>)/gi,
    svgContent: /<svg[\s\S]*?>[\s\S]*?<\/svg>/gi,
    selfClosingSvg: /<svg\s*\/[^>]*on\w+\s*=\s*[^>]*>/gi,
    noSpaceSvg: /<svg\/[^>]*on\w+\s*=\s*[^>]*>/gi,
    xmpBreakout: /<xmp\b[^>]*>[^<]*<\/xmp><[^>]*on\w+\s*=\s*[^>]*>/gi,
    mixedCaseEvents: /<[^>]+\s+on\w+\s*=\s*(['"`]?)[\s\S]*?\1[^>]*>/gi,
    mathMLContent: /<math[\s\S]*?>[\s\S]*?<\/math>/gi,
    inlineEvent: /<[^>]+\s+on\w+\s*=\s*(['"`]?)[\s\S]*?\1[^>]*>/gi,
  },

  // JavaScript context patterns
  javascript: {
    eventHandlers: /\s+on\w+\s*=\s*(['"`]?)[^>]*\1/gi,
    genericEvent: /on\w+\s*=/gi,
    unquotedEventHandlers: /<[^>]*\s+on\w+\s*=\s*[^'"` >][^>]*/gi,
    jsUris: /\b(href|src|action|data)\s*=\s*(['"`])\s*javascript:.*?\2/gi,
    directEval: /\beval\s*\(/gi,
    newFunction: /\bnew\s+Function\s*\(/gi,
    functionConstructor: /\bFunction\s*\(/gi,
    documentWrite: /\bdocument\.(write|writeln)\s*\(/gi,
    innerHtml: /\.(innerHTML|outerHTML)\s*=\s*/gi,
    documentCookie: /\bdocument\.cookie\b/gi,
    windowLocation: /\blocation\b\s*=\s*/gi,
    setTimeout: /\bsetTimeout\s*\(\s*(['"`])/gi,
    setInterval: /\bsetInterval\s*\(\s*(['"`])/gi,
    backtick: /`/gi,
  },

  // URL context patterns
  url: {
    dataUri: /data:\s*(?!image\/)/gi,
    javascriptUri: /javascript:/gi,
    vbscriptUri: /vbscript:/gi,
    dataImageSvg: /data:image\/svg/gi,
    encodedJavaScriptUri:
      /(?:%(?:25)?(?:22)?%(?:25)?(?:27)?)?%(?:25)?(?:6A|4A)(?:%25)?(?:61|41)(?:%25)?(?:76|56)(?:%25)?(?:61|41)(?:%25)?(?:73|53)(?:%25)?(?:63|43)(?:%25)?(?:72|52)(?:%25)?(?:69|49)(?:%25)?(?:70|50)(?:%25)?(?:74|54)(?:%25)?(?:3A|%3a)/gi,
  },

  // CSS context patterns
  css: {
    cssExpression: /expression\s*\(/gi,
    cssUrl: /url\s*\(\s*(['"]?)(?!data:image\/|https?:\/\/|\/\/|\/)/gi,
    cssImport: /@import\s+['"]/gi,
  },

  // Advanced evasion techniques
  evasion: {
    hexEncoding: /&#x[0-9a-f]{2,6};/gi,
    decimalEncoding: /&#[0-9]{2,6};/gi,
    nullByte: /\\x00/gi,
    unicodeEvasion: /\\u[0-9a-f]{4}/gi,
    commentedCode: /\/\*.*?\*\//gi,
    multipleEncodings: /%(?:[0-9a-f]{2}|u[0-9a-f]{4})/gi,
  },
};

export class XssModule implements SnafModule {
  name = "xss";
  enabled = true;
  private config: XssModuleConfig;
  private readonly customPatterns: RegExp[] = [];
  private whitelistedDomains: Set<string> = new Set();
  // noinspection JSMismatchedCollectionQueryUpdate
  private whitelistedPaths: Set<string> = new Set();
  private readonly reportOnly: boolean = false;

  constructor(config: XssModuleConfig) {
    this.config = config;

    // Initialize whitelist if provided
    if (config.whitelistedDomains) {
      this.whitelistedDomains = new Set(config.whitelistedDomains);
    }

    // Initialize custom patterns if provided
    if (config.customPayloads) {
      this.customPatterns = config.customPayloads.map(
        (pattern) => new RegExp(pattern, "gi"),
      );
    }

    // Set report-only mode if specified
    this.reportOnly = config.blockMode === "report";
  }

  analyze(ctx: SnafContext): SnafAction {
    // Check if the request should be whitelisted
    if (this.isWhitelisted(ctx)) {
      return { action: "allow" };
    }

    const result: XssDetectionResult = {
      detected: false,
      count: 0,
      vectors: [],
      contexts: new Set<string>(),
      severity: "low",
      sanitizedFields: {},
    };

    // Clone objects to avoid mutating the original during analysis
    const bodyClone = ctx.body ? this.deepClone(ctx.body) : {};
    const queryClone = ctx.query ? this.deepClone(ctx.query) : {};
    this.normalizeInput(bodyClone);
    this.normalizeInput(queryClone);
    // Process all potential XSS vectors based on config
    if (this.config.inlineEventHandlers) {
      this.processJavaScriptContext(ctx, bodyClone, queryClone, result);
    }

    if (this.config.dynamicContent) {
      this.processHtmlContext(ctx, bodyClone, queryClone, result);
    }

    if (this.config.urlParameters) {
      this.processUrlContext(ctx, bodyClone, queryClone, result);
    }

    if (this.config.formInputs) {
      this.processFormInputs(ctx, bodyClone, queryClone, result);
    }

    if (this.config.userGeneratedContent) {
      this.processUserGeneratedContent(ctx, bodyClone, queryClone, result);
      this.processCssContext(ctx, bodyClone, queryClone, result);
    }

    // Process custom patterns if defined
    if (this.customPatterns.length > 0) {
      this.processCustomPatterns(ctx, bodyClone, queryClone, result);
    }

    // Calculate severity based on detection context and count
    this.calculateSeverity(result);

    // Handle the results based on mode
    if (result.detected) {
      // Log the detection for potential monitoring/alerting
      this.logDetection(ctx, result);

      // If in report-only mode, allow but attach info to request
      if (this.reportOnly) {
        (ctx.req as any).__xssDetection = result;
        return { action: "allow" };
      }

      if (this.config.blockMode === "block") {
        return {
          action: "block",
          reason: `XSS attack detected: ${result.vectors.join(", ")} (Severity: ${result.severity})`,
        };
      } else if (
        this.config.blockMode === "sanitize" ||
        this.config.blockMode === "remove"
      ) {
        return {
          action: "sanitize",
          sanitized: { body: bodyClone, query: queryClone },
          reason: `XSS sanitized: ${result.vectors.join(", ")} (Severity: ${result.severity})`,
        };
      }
    }

    return { action: "allow" };
  }

  private isWhitelisted(ctx: SnafContext): boolean {
    // Check if origin/referrer is in whitelisted domains
    const origin = ctx.headers?.["origin"] as string;
    const referrer = ctx.headers?.["referer"] as string;

    if (origin && this.isWhitelistedDomain(origin)) return true;
    if (referrer && this.isWhitelistedDomain(referrer)) return true;

    // Check if the path is whitelisted
    return ctx.req.path && this.whitelistedPaths.has(ctx.req.path);
  }

  private isWhitelistedDomain(url: string): boolean {
    try {
      const domain = new URL(url).hostname;
      return this.whitelistedDomains.has(domain);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (e) {
      return false;
    }
  }

  private deepClone(obj: any): any {
    return JSON.parse(JSON.stringify(obj));
  }

  private calculateSeverity(result: XssDetectionResult): void {
    // Determine severity based on detection context and count
    if (result.contexts.has("javascript") && result.count > 5) {
      result.severity = "critical";
    } else if (result.contexts.has("javascript") || result.count > 10) {
      result.severity = "high";
    } else if (result.contexts.has("html") && result.count > 3) {
      result.severity = "medium";
    } else {
      result.severity = "low";
    }
  }

  private logDetection(ctx: SnafContext, result: XssDetectionResult): void {
    // In a real implementation, this might log to a database, SIEM, etc.
    console.warn(
      `[SNAF XSS] Attack detected - Severity: ${result.severity}, Vectors: ${result.vectors.join(", ")}, Path: ${ctx.req.path}`,
    );
  }

  // Process JavaScript context XSS vectors
  private processJavaScriptContext(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    const patterns = XSS_PATTERNS.javascript;

    for (const [key, pattern] of Object.entries(patterns)) {
      this.checkAndSanitize(bodyClone, pattern, `js-${key}`, result);
      this.checkAndSanitize(queryClone, pattern, `js-${key}`, result);
    }

    if (result.vectors.some((v) => v.startsWith("js-"))) {
      result.contexts.add("javascript");
    }
  }

  // Process HTML context XSS vectors
  private processHtmlContext(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    const patterns = XSS_PATTERNS.html;
    const svgPayloadPattern =
      /<svg[^>]*on\w+\s*=\s*[^>]*(alert|prompt|confirm|eval|function|\()/gi;
    const xmpPayloadPattern =
      /<xmp[^>]*>.*?<\/xmp><[^>]*on\w+\s*=\s*[^>]*(alert|prompt|confirm|eval|function|\()/gi;

    this.checkAndSanitize(
      bodyClone,
      svgPayloadPattern,
      "html-svg-payload",
      result,
    );
    this.checkAndSanitize(
      queryClone,
      svgPayloadPattern,
      "html-svg-payload",
      result,
    );
    this.checkAndSanitize(
      bodyClone,
      xmpPayloadPattern,
      "html-xmp-breakout",
      result,
    );
    this.checkAndSanitize(
      queryClone,
      xmpPayloadPattern,
      "html-xmp-breakout",
      result,
    );
    for (const [key, pattern] of Object.entries(patterns)) {
      this.checkAndSanitize(bodyClone, pattern, `html-${key}`, result);
      this.checkAndSanitize(queryClone, pattern, `html-${key}`, result);
    }

    if (result.vectors.some((v) => v.startsWith("html-"))) {
      result.contexts.add("html");
    }
  }

  // Process URL context XSS vectors
  private processUrlContext(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    const patterns = XSS_PATTERNS.url;

    for (const [key, pattern] of Object.entries(patterns)) {
      this.checkAndSanitize(bodyClone, pattern, `url-${key}`, result);
      this.checkAndSanitize(queryClone, pattern, `url-${key}`, result);
    }

    if (result.vectors.some((v) => v.startsWith("url-"))) {
      result.contexts.add("url");
    }
  }

  // Process CSS context XSS vectors
  private processCssContext(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    const patterns = XSS_PATTERNS.css;

    for (const [key, pattern] of Object.entries(patterns)) {
      this.checkAndSanitize(bodyClone, pattern, `css-${key}`, result);
      this.checkAndSanitize(queryClone, pattern, `css-${key}`, result);
    }

    if (result.vectors.some((v) => v.startsWith("css-"))) {
      result.contexts.add("css");
    }
  }

  private processFormInputs(
    _ctx: SnafContext,
    bodyClone: any,
    _queryClone: any,
    result: XssDetectionResult,
  ): void {
    const iframePattern = /<iframe\b[^>]*>/gi;
    const objectPattern = /<object\b[^>]*>/gi;
    const embedPattern = /<embed\b[^>]*>/gi;
    const formPattern = /<form\b[^>]*>/gi;
    const buttonPattern = /<button\b[^>]*>/gi;
    const inputPattern = /<input\b[^>]*>/gi;

    this.checkAndSanitize(bodyClone, iframePattern, "form-iframe", result);
    this.checkAndSanitize(bodyClone, objectPattern, "form-object", result);
    this.checkAndSanitize(bodyClone, embedPattern, "form-embed", result);
    this.checkAndSanitize(bodyClone, formPattern, "form-tag", result);
    this.checkAndSanitize(bodyClone, buttonPattern, "form-button", result);
    this.checkAndSanitize(bodyClone, inputPattern, "form-input", result);

    if (result.vectors.some((v) => v.startsWith("form-"))) {
      result.contexts.add("html");
    }
  }
  private normalizeInput(obj: any): void {
    if (!obj) return;
    for (const key in obj) {
      if (typeof obj[key] === "string") {
        obj[key] = this.decodeSafe(obj[key]);
      } else if (typeof obj[key] === "object" && obj[key] !== null) {
        this.normalizeInput(obj[key]);
      }
    }
  }
  // idk if this is safe
  private decodeSafe(str: string): string {
    if (!str) return str;

    // Handle multiple levels of URL encoding
    let s = str;
    let prev = "";
    while (s !== prev) {
      prev = s;
      try {
        s = decodeURIComponent(s);
      } catch {
        break; // Stop if we can't decode further
      }
    }

    // Handle HTML entity encoding
    return s
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&apos;/gi, "'")
      .replace(/&amp;/gi, "&")
      .replace(/&#x([0-9a-f]+);/gi, (_m, hex) =>
        String.fromCharCode(parseInt(hex, 16)),
      )
      .replace(/&#(\d+);/g, (_m, dec) =>
        String.fromCharCode(parseInt(dec, 10)),
      );
  }
  private processUserGeneratedContent(
    ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    // Advanced evasion techniques
    const patterns = XSS_PATTERNS.evasion;

    for (const [key, pattern] of Object.entries(patterns)) {
      this.checkAndSanitize(bodyClone, pattern, `evasion-${key}`, result, true);
      this.checkAndSanitize(
        queryClone,
        pattern,
        `evasion-${key}`,
        result,
        true,
      );
    }

    // Check for polyglot XSS payloads
    const polyglotPatterns = [
      /jaVasCript:\/\*-\/\*`\/\*`\/\*`\/\*`\/\*`\/\*`\*\//gi,
      /">'><script>alert\("XSS"\)<\/script>/gi,
      /javascript:\/\*-\/\*`\/\*'\/\*"\/\*\*\/\(\/* \*\/onerror=alert\('1'\)\)\/\/%0D%0A%0d%0a\/\//gi,
    ];

    for (const pattern of polyglotPatterns) {
      this.checkAndSanitize(bodyClone, pattern, "advanced-polyglot", result);
      this.checkAndSanitize(queryClone, pattern, "advanced-polyglot", result);
    }

    // Special check for sensitive params if defined
    if (this.config.sensitiveParams?.length) {
      this.checkSensitiveParams(ctx, bodyClone, queryClone, result);
    }
  }

  private processCustomPatterns(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    for (let i = 0; i < this.customPatterns.length; i++) {
      this.checkAndSanitize(
        bodyClone,
        this.customPatterns[i],
        `custom-pattern-${i}`,
        result,
      );
      this.checkAndSanitize(
        queryClone,
        this.customPatterns[i],
        `custom-pattern-${i}`,
        result,
      );
    }
  }

  private checkSensitiveParams(
    _ctx: SnafContext,
    bodyClone: any,
    queryClone: any,
    result: XssDetectionResult,
  ): void {
    const sensitiveParams = this.config.sensitiveParams || [];

    // Apply stricter checks for sensitive parameters
    for (const param of sensitiveParams) {
      if (bodyClone && param in bodyClone) {
        // Extra paranoid check for any HTML-like content
        const value = bodyClone[param];
        if (typeof value === "string" && /<[^>]+>/i.test(value)) {
          result.detected = true;
          result.count++;
          result.vectors.push(`sensitive-param-${param}`);
          result.contexts.add("sensitive");

          // Sanitize by completely removing HTML
          const original = bodyClone[param];
          bodyClone[param] = bodyClone[param].replace(/<[^>]*>/g, "");
          result.sanitizedFields[param] = {
            original,
            sanitized: bodyClone[param],
          };
        }
      }

      if (queryClone && param in queryClone) {
        const value = queryClone[param];
        if (typeof value === "string" && /<[^>]+>/i.test(value)) {
          result.detected = true;
          result.count++;
          result.vectors.push(`sensitive-param-${param}`);
          result.contexts.add("sensitive");

          // Sanitize by completely removing HTML
          const original = queryClone[param];
          queryClone[param] = queryClone[param].replace(/<[^>]*>/g, "");
          result.sanitizedFields[param] = {
            original,
            sanitized: queryClone[param],
          };
        }
      }
    }
  }

  // Enhanced check and sanitize function that maintains record of sanitized fields
  private checkAndSanitize(
    obj: any,
    pattern: RegExp,
    vectorName: string,
    result: XssDetectionResult,
    justCheck: boolean = false,
  ): void {
    if (!obj) return;

    for (const key in obj) {
      if (typeof obj[key] === "string") {
        const value = obj[key];
        const matches = value.match(pattern);

        if (matches && matches.length > 0) {
          result.detected = true;
          result.count += matches.length;
          if (!result.vectors.includes(vectorName)) {
            result.vectors.push(vectorName);
          }

          // Sanitize by removing the malicious content
          if (!justCheck) {
            const original = obj[key];
            obj[key] = obj[key].replace(pattern, "");

            // Keep track of sanitized fields
            result.sanitizedFields[key] = {
              original,
              sanitized: obj[key],
            };
          }
        }
      } else if (typeof obj[key] === "object" && obj[key] !== null) {
        // Recursive check for nested shit
        this.checkAndSanitize(obj[key], pattern, vectorName, result, justCheck);
      }
    }
  }
}
