/**
 * GhostProtocol AI Inference Engine
 * 100% Client-Side Native REST Pipeline with Multi-Model Fallback Cascade
 * Optimized for low latency (<1.5s), minimal token consumption, and rate-limit resilience.
 */

export type MissionType = 'dark_patterns' | 'gdpr_ultimatum' | 'jargon_scrub';
export type ModelChoice = 'auto' | 'gemini-3.8-flash' | 'gemini-3.8-pro';
export type AnalysisDepth = 'quick' | 'detailed';

export interface ForensicPromptPayload {
  apiKey: string;
  model: ModelChoice;
  mission: MissionType;
  depth?: AnalysisDepth;
  emailText: string;
  metadata?: {
    subject?: string;
    from?: string;
    date?: string;
    heuristicsRiskScore?: number;
    flaggedBadges?: string[];
  };
}

export interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface ForensicResult {
  markdown: string;
  modelUsed: string;
  latencyMs: number;
  depth: AnalysisDepth;
  fallbackTriggered?: boolean;
  extractedSubject?: string;
  cached?: boolean;
  tokenUsage?: TokenUsage;
}

const SYSTEM_INSTRUCTION_QUICK = `You are GhostProtocol Fast Summary.
Your goal is to give a busy user a 10-second ultra-concise read.
STRICT BREVITY RULES:
- Maximum 75 words total.
- Use only short, punchy bullet points.
- No long essays, no repetitive filler, and no legal theory.
- Answer directly: What is the risk? What is the trick? What should they do?`;

const SYSTEM_INSTRUCTION_DETAILED = `You are GhostProtocol Lead Forensics: an elite cybersecurity compliance auditor and regulatory enforcement specialist.
Provide an in-depth forensic audit with precise regulatory citations (GDPR Art. 17/7(3), CCPA § 1798.105, EU Digital Services Act Art. 25, US FTC Act Sec. 5).`;

/**
 * Builds prompt tailored for either Fast Summary or Deep Audit
 */
function buildTaskPrompt(payload: ForensicPromptPayload, depth: AnalysisDepth): string {
  const { mission, emailText, metadata } = payload;
  const meta = metadata?.subject ? `SUBJECT: "${metadata.subject}" | FROM: "${metadata.from || 'Unknown'}"\n` : '';

  // Fast Summary (Ultra-concise 10-second read under 75 words)
  if (depth === 'quick') {
    switch (mission) {
      case 'dark_patterns':
        return `${meta}Give an ultra-fast 10-second summary of this email. Maximum 70 words total.

Format strictly as:
- 🚨 **Verdict**: [Risk rating (Low/Medium/High/Critical) + 1 brief sentence explaining why]
- ⚠️ **The Trick**: [1-2 short bullet points highlighting the sneaky catch, e.g. fake timer, hidden fee, or auto-renew]
- 🛡️ **Action**: [1 simple next step for the user]

EMAIL:
${emailText}`;

      case 'gdpr_ultimatum':
        return `${meta}Draft a short, ready-to-send 5-line GDPR Art. 17 data deletion email. Maximum 75 words total.
Start with: \`SUBJECT: Data Erasure Request (GDPR Art. 17) - [YOUR NAME]\`
Include placeholder tokens: [YOUR NAME], [ACCOUNT EMAIL], [DATE].

EMAIL:
${emailText}`;

      case 'jargon_scrub':
        return `${meta}Translate this corporate email into plain English in under 70 words:
- 💡 **What Happened**: [1 clear sentence explaining what the company actually did without PR spin]
- 🔄 **Translation Table**: [A 2-row mini table: "Corporate PR" vs "Real Meaning"]
- ⚠️ **The Catch**: [1 sentence on any price hike, lost benefit, or forced terms]

EMAIL:
${emailText}`;
    }
  }

  // Detailed Deep Audit (On-Demand: Exhaustive legal analysis)
  switch (mission) {
    case 'dark_patterns':
      return `${meta}COMPREHENSIVE FORENSIC AUDIT: DECEPTIVE PATTERNS & COMPLIANCE VIOLATIONS

Provide an exhaustive audit:
1. **EXECUTIVE THREAT SUMMARY**: Deceptive Severity Rating & cognitive manipulation vector.
2. **ITEMIZED DECEPTIVE TACTICS**: For each tactic (Roach Motel, Confirm-Shaming, False Urgency, Disguised Terms), detail:
   - Direct quote evidence
   - Psychological mechanism
   - Applicable regulatory statute (FTC Act § 5, EU DSA Art. 25, or GDPR consent rules)
3. **FINANCIAL & DATA SURVEILLANCE AUDIT**: Hidden fees, negative-option billings, or tracking beacons.
4. **TACTICAL DEFENSE PROTOCOL**: Recommended regulatory complaint text or consumer defense steps.

EMAIL:
${emailText}`;

    case 'gdpr_ultimatum':
      return `${meta}FORMAL LEGAL DEMAND: DATA SUBJECT ERASURE DIRECTIVE (GDPR / CCPA / DPDPA)

Draft an ironclad, exhaustive legal ultimatum under GDPR Article 17, Article 7(3), Article 21, and CCPA § 1798.105:
1. Mandatory demands: immediate deletion of all telemetry, backups, sub-processor data, and profiling.
2. Statutory 30-day compliance deadline and notification of automatic escalation to supervisory authorities (CNIL, ICO, FTC).
3. Use standardized bracket tokens: [YOUR FULL LEGAL NAME], [YOUR ACCOUNT EMAIL], [DATE].
4. Include: \`SUBJECT: Formal Notice of Erasure Request under GDPR Art. 17 / CCPA - [YOUR NAME]\`.

EMAIL:
${emailText}`;

    case 'jargon_scrub':
      return `${meta}CORPORATE DE-OBFUSCATION MATRIX

1. **UNVARNISHED EXECUTIVE SUMMARY**: Candid breakdown of the real corporate motive.
2. **THE PR SPIN TRANSLATION TABLE**: Two-column Markdown table ("Corporate Weasel Words" vs "The Plain-English Truth").
3. **CONSUMER RIGHTS & PRICING IMPACT**: Detailed breakdown of revoked perks, stealth price adjustments, or arbitration clauses.
4. **RECOMMENDED RESPONSE CHECKLIST**: Immediate tactical checklist for the subscriber.

EMAIL:
${emailText}`;
  }
}

/**
 * Direct native client to Google Generative Language REST API.
 * Tries v1beta first; if model is not found in v1beta, seamlessly falls back to v1 production.
 * Uses native browser fetch() with an AbortController timeout to prevent browser stalls.
 */
async function generateViaRest(
  apiKey: string,
  model: string,
  prompt: string,
  systemInstruction: string,
  maxOutputTokens: number,
  timeoutMs: number = 30000
): Promise<{ text: string; tokenUsage?: TokenUsage }> {
  const cleanModel = model.replace(/^models\//, '');
  const apiVersions = ['v1beta', 'v1'];
  let lastError: Error | null = null;

  for (const apiVer of apiVersions) {
    // Automatic retry loop for temporary high-demand spikes (HTTP 503 / 429)
    for (let attempt = 0; attempt < 3; attempt++) {
      const endpoint = `https://generativelanguage.googleapis.com/${apiVer}/models/${cleanModel}:generateContent?key=${apiKey}`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const body: any = {
          contents: [{ role: 'user', parts: [{ text: `${systemInstruction}\n\n${prompt}` }] }],
          generationConfig: {
            temperature: 0.2,
            maxOutputTokens,
            topP: 0.95,
          },
        };

        if (apiVer === 'v1beta') {
          body.systemInstruction = { parts: [{ text: systemInstruction }] };
        }

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          const message = errorData?.error?.message || `HTTP ${response.status}: ${response.statusText}`;

          // Detect temporary Google high-demand server spike and automatically retry after delay
          const isHighDemand = response.status === 503 || response.status === 429 || message.toLowerCase().includes('high demand') || message.toLowerCase().includes('spikes in demand');
          if (isHighDemand && attempt < 2) {
            console.warn(`[GhostProtocol] ${cleanModel} experiencing temporary Google server demand spike. Auto-retrying in ${1.5 * (attempt + 1)}s...`);
            await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
            continue; // Retry attempt
          }

          // If not found on v1beta, fall through to try v1!
          if (response.status === 404 || message.includes('not found for API version')) {
            lastError = new Error(`API Error (${cleanModel} on ${apiVer}): ${message}`);
            break; // Try next apiVer
          }
          throw new Error(`API Error (${cleanModel}): ${message}`);
        }

        const data = await response.json();
        const candidate = data.candidates?.[0];
        const text = candidate?.content?.parts?.[0]?.text;

        if (!text) {
          const finishReason = candidate?.finishReason || 'NO_TEXT';
          throw new Error(`Model ${cleanModel} returned no text content (${finishReason}).`);
        }

        let tokenUsage: TokenUsage | undefined = undefined;
        if (data.usageMetadata) {
          tokenUsage = {
            promptTokens: data.usageMetadata.promptTokenCount || 0,
            completionTokens: data.usageMetadata.candidatesTokenCount || 0,
            totalTokens: data.usageMetadata.totalTokenCount || ((data.usageMetadata.promptTokenCount || 0) + (data.usageMetadata.candidatesTokenCount || 0)),
          };
        }

        return { text, tokenUsage };
      } catch (err: any) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          throw new Error(`Model ${cleanModel} timed out after ${timeoutMs / 1000}s`);
        }
        lastError = err;
        if (err.message && err.message.includes('not found for API version')) {
          break; // Try next apiVer
        }
        if (attempt < 2 && (err.message?.toLowerCase().includes('high demand') || err.message?.includes('503'))) {
          await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        throw err;
      }
    }
  }

  throw lastError || new Error(`Failed to generate with ${cleanModel}`);
}

/**
 * Queries Google's ModelService.ListModels endpoint to dynamically discover
 * the exact models authorized for this user's API key.
 */
export async function discoverAvailableModels(apiKey: string): Promise<string[]> {
  if (!apiKey || !apiKey.trim()) return [];
  const cleanKey = apiKey.trim();

  for (const apiVer of ['v1beta', 'v1']) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/${apiVer}/models?key=${cleanKey}`;
      const res = await fetch(endpoint);
      if (res.ok) {
        const data = await res.json();
        if (data.models && Array.isArray(data.models)) {
          const models: string[] = data.models
            .filter((m: any) => m.supportedGenerationMethods && m.supportedGenerationMethods.includes('generateContent'))
            .map((m: any) => m.name.replace(/^models\//, ''));

          if (models.length > 0) {
            console.log(`[GhostProtocol] Discovered ${models.length} active models via ${apiVer}:`, models);
            return models;
          }
        }
      }
    } catch (e) {
      console.warn(`[GhostProtocol] ListModels attempt on ${apiVer} warning:`, e);
    }
  }
  return [];
}

/**
 * Smart pre-compressor: Strips useless boilerplate, tracking parameters, base64 images,
 * and empty line floods before sending to Gemini.
 * Saves input tokens and speeds up inference by cutting Time-to-First-Token (TTFT).
 */
function compressEmailPayload(raw: string, depth: AnalysisDepth): string {
  let text = raw;

  // 1. Strip massive base64 inline images and data URIs (huge token wasters)
  text = text.replace(/data:image\/[a-zA-Z0-9.+-]+;base64,[a-zA-Z0-9+/=]{40,}/gi, '[image removed]');

  // 2. Strip tracking query params from URLs (utm_*, fbclid, mc_cid, etc.)
  text = text.replace(/(\bhttps?:\/\/[^\s?#]+)\?[^\s#]+/gi, (_: string, base: string) => {
    return `${base}?[cleaned]`;
  });

  // 3. Collapse multi-spaces and 3+ consecutive newlines to 2 newlines
  text = text.replace(/[ \t]{2,}/g, ' ');
  text = text.replace(/\n{3,}/g, '\n\n').trim();

  // 4. Intelligent truncation limit based on depth
  const maxChars = depth === 'quick' ? 3500 : 7000;
  if (text.length > maxChars) {
    text = text.slice(0, maxChars) + '\n\n[... Email payload truncated for speed ...]';
  }

  return text;
}

let discoveredModelsCache: string[] = [];

/**
 * In-memory sticky cache of the last model that succeeded on this user's API key.
 * Prevents repeating fallback checks on subsequent requests, giving ~1.1s instant responses.
 */
let lastWorkingModel: string | null = null;

/**
 * Executes inference with automatic smart fallback across models
 */
export async function executeForensicAnalysis(payload: ForensicPromptPayload): Promise<ForensicResult> {
  if (!payload.apiKey || !payload.apiKey.trim()) {
    throw new Error('API Key missing. Enter your Gemini API key in the top configuration header.');
  }

  if (!payload.emailText || !payload.emailText.trim()) {
    throw new Error('Email payload is empty. Drop an .eml file or paste email text to begin.');
  }

  const startTime = performance.now();
  const depth: AnalysisDepth = payload.depth || 'quick';
  const maxOutputTokens = depth === 'quick' ? 220 : 1400;
  const systemInstruction = depth === 'quick' ? SYSTEM_INSTRUCTION_QUICK : SYSTEM_INSTRUCTION_DETAILED;
  
  // Clean email payload
  const sanitizedPayload = {
    ...payload,
    emailText: compressEmailPayload(payload.emailText, depth),
  };
  const taskPrompt = buildTaskPrompt(sanitizedPayload, depth);

  // Auto-discover models from Google API if not yet discovered
  if (discoveredModelsCache.length === 0) {
    try {
      discoveredModelsCache = await discoverAvailableModels(payload.apiKey);
    } catch (e) {
      console.warn('[GhostProtocol] Model discovery check:', e);
    }
  }

  // Model fallback chain: prioritized by active availability
  const candidateModels: string[] = [];
  const modelStr = payload.model as string;

  if (discoveredModelsCache.length > 0) {
    if (modelStr && modelStr !== 'auto' && discoveredModelsCache.includes(modelStr)) {
      candidateModels.push(modelStr);
    }
    if (lastWorkingModel && discoveredModelsCache.includes(lastWorkingModel)) {
      if (!candidateModels.includes(lastWorkingModel)) candidateModels.push(lastWorkingModel);
    }
    const flashList = discoveredModelsCache.filter((m) => m.includes('flash'));
    const proList = discoveredModelsCache.filter((m) => !m.includes('flash'));
    for (const m of [...flashList, ...proList]) {
      if (!candidateModels.includes(m)) candidateModels.push(m);
    }
  } else {
    if (modelStr && modelStr !== 'auto') {
      candidateModels.push(modelStr);
    }
    if (lastWorkingModel && !candidateModels.includes(lastWorkingModel)) {
      candidateModels.push(lastWorkingModel);
    }
    for (const m of ['gemini-3.8-flash', 'gemini-3.8-pro']) {
      if (!candidateModels.includes(m)) candidateModels.push(m);
    }
  }

  let markdown = '';
  let successfulModel = '';
  let fallbackTriggered = false;
  let tokenUsage: TokenUsage | undefined = undefined;
  const failureLog: string[] = [];

  // Execute via direct native fetch with timeout
  for (let i = 0; i < candidateModels.length; i++) {
    const modelToTry = candidateModels[i];
    try {
      const restRes = await generateViaRest(
        payload.apiKey.trim(),
        modelToTry,
        taskPrompt,
        systemInstruction,
        maxOutputTokens,
        30000 // 30s timeout per candidate to prevent premature aborts while generating
      );
      markdown = restRes.text;
      tokenUsage = restRes.tokenUsage;
      successfulModel = modelToTry;
      fallbackTriggered = i > 0;
      lastWorkingModel = successfulModel;
      break;
    } catch (restError: any) {
      failureLog.push(`${modelToTry} (${restError.message})`);
      console.warn(`Model ${modelToTry} attempt failed, cascading:`, restError.message);
    }
  }

  if (!markdown) {
    throw new Error(`All model candidates exhausted. Details: ${failureLog.join(' | ')}. Please check your API key quota in Google AI Studio.`);
  }

  const latencyMs = Math.round(performance.now() - startTime);

  // Extract legal email subject line if drafting GDPR notice
  let extractedSubject = undefined;
  if (payload.mission === 'gdpr_ultimatum') {
    const subjectMatch = markdown.match(/SUBJECT:\s*([^\n\r]+)/i);
    if (subjectMatch) {
      extractedSubject = subjectMatch[1].trim();
    } else {
      extractedSubject = `Formal Notice: Data Erasure Request (GDPR Art. 17 / CCPA)`;
    }
  }

  return {
    markdown,
    modelUsed: successfulModel,
    latencyMs,
    depth,
    fallbackTriggered,
    extractedSubject,
    tokenUsage,
  };
}
