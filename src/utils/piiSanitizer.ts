/**
 * GhostProtocol Zero-Leakage Client-Side PII Sanitizer
 * Anonymizes high-risk personal data in browser memory prior to API transmission.
 */

export interface SanitizationResult {
  text: string;
  totalRedacted: number;
  redactedCategories: Record<string, number>;
}

export function sanitizePii(rawText: string, options: { maskEmails?: boolean } = { maskEmails: true }): SanitizationResult {
  let text = rawText;
  const categories: Record<string, number> = {
    'Phone Numbers': 0,
    'Credit Cards / Financial': 0,
    'Social Security / National IDs': 0,
    'Physical Addresses': 0,
    'Personal Emails': 0,
  };

  // 1. Credit Cards & Financial account numbers (Visa, MC, Amex patterns)
  const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{4}[ -]?\d{6}[ -]?\d{5}\b/g;
  text = text.replace(ccRegex, () => {
    categories['Credit Cards / Financial']++;
    return '[REDACTED_FINANCIAL_ACCOUNT]';
  });

  // IBAN Numbers
  const ibanRegex = /\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9]{4}){4,7}\b/g;
  text = text.replace(ibanRegex, () => {
    categories['Credit Cards / Financial']++;
    return '[REDACTED_IBAN]';
  });

  // 2. Social Security Numbers (US / international 9-digit formats)
  const ssnRegex = /\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g;
  text = text.replace(ssnRegex, () => {
    categories['Social Security / National IDs']++;
    return '[REDACTED_NATIONAL_ID]';
  });

  // 3. International & US Phone Numbers
  const phoneRegex = /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  text = text.replace(phoneRegex, (match: string) => {
    // Avoid redacting simple dates like 2026-10-31
    if (match.match(/^20\d{2}[-/]\d{2}[-/]\d{2}$/)) return match;
    categories['Phone Numbers']++;
    return '[REDACTED_PHONE]';
  });

  // 4. Physical Street Addresses (heuristic pattern)
  const addressRegex = /\b\d{1,5}\s+[A-Za-z0-9\s.,]{3,30}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b(?:,\s*[A-Za-z\s]+)?(?:\s+\d{5}(?:-\d{4})?)?/gi;
  text = text.replace(addressRegex, () => {
    categories['Physical Addresses']++;
    return '[REDACTED_PHYSICAL_ADDRESS]';
  });

  // 5. Personal Email Addresses (Preserving company domains if obvious support/privacy desks)
  if (options.maskEmails) {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;
    text = text.replace(emailRegex, (match: string, domain: string) => {
      // Don't mask common public company service desks to keep context
      const publicDomains = ['privacy@', 'dpo@', 'support@', 'legal@', 'compliance@'];
      const isPublicDesk = publicDomains.some((d) => match.toLowerCase().startsWith(d));
      if (isPublicDesk) return match;

      categories['Personal Emails']++;
      return `[REDACTED_USER_EMAIL@${domain}]`;
    });
  }

  const totalRedacted = Object.values(categories).reduce((sum, count) => sum + count, 0);

  return {
    text,
    totalRedacted,
    redactedCategories: categories,
  };
}
