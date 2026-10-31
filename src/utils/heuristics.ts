/**
 * GhostProtocol Local Heuristic Sentinel
 * Real-time, zero-latency detection of tracking pixels, CSS cloaking, and predatory patterns.
 */

export interface HeuristicBadge {
  id: string;
  category: 'TRACKING' | 'CLOAKING' | 'MANIPULATION' | 'COMPLIANCE';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  evidence?: string;
}

export interface HeuristicReport {
  riskScore: number; // 0 to 100
  riskLevel: 'CLEAN' | 'LOW' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
  badges: HeuristicBadge[];
  summary: string;
}

export function scanEmailHeuristics(rawInput: string, rawHtml: string | null, listUnsubscribeHeader: string | null): HeuristicReport {
  const badges: HeuristicBadge[] = [];
  const text = rawInput.toLowerCase();
  const html = (rawHtml || rawInput).toLowerCase();

  // 1. Tracking Pixel Sentinel
  const trackingPixelRegex = /<img[^>]+(?:width=["']?[01]["']?|height=["']?[01]["']?|style=["'][^"']*(?:width:\s*[01]px|height:\s*[01]px|display:\s*none)[^"']*)[^>]*>/gi;
  const pixelMatches = html.match(trackingPixelRegex);
  const trackerDomainRegex = /(?:https?:\/\/)?(?:click\.|trk\.|tracking\.|stats\.|track\.|pixel\.|metrics\.)[a-z0-9.-]+\.[a-z]{2,}/gi;
  const trackerLinks = html.match(trackerDomainRegex);

  if (pixelMatches && pixelMatches.length > 0) {
    badges.push({
      id: 'TRACKER_PIXEL_DETECTED',
      category: 'TRACKING',
      severity: 'HIGH',
      title: 'Hidden Tracking Beacon Detected',
      description: `Identified ${pixelMatches.length} zero-pixel or invisible image beacon(s) used for read receipts and IP/location telemetry without affirmative consent.`,
      evidence: pixelMatches[0].slice(0, 80) + '...',
    });
  } else if (trackerLinks && trackerLinks.length > 3) {
    badges.push({
      id: 'HEAVY_REDIRECT_TRACKING',
      category: 'TRACKING',
      severity: 'MEDIUM',
      title: 'Aggressive Redirect Tracking',
      description: `Found ${trackerLinks.length} rerouted tracking URLs designed to log link engagement metrics.`,
    });
  }

  // 2. CSS Cloaking & Zero-Opacity Typography
  const cloakedCssRegex = /(?:font-size:\s*(?:0|1|2)px|color:\s*(?:transparent|#fff(?:fff)?|rgba?\([^)]+,0\))|opacity:\s*0|visibility:\s*hidden|display:\s*none)/gi;
  const cloakedMatches = html.match(cloakedCssRegex);

  if (cloakedMatches && cloakedMatches.length > 0) {
    badges.push({
      id: 'CLOAKED_TYPOGRAPHY',
      category: 'CLOAKING',
      severity: 'CRITICAL',
      title: 'CSS Cloaking / Micro-Print',
      description: 'Found hidden CSS rules (zero-pixel font or invisible opacity) frequently used to disguise legal caveats, affiliate disclaimers, or auto-renew terms.',
      evidence: cloakedMatches[0],
    });
  }

  // 3. Confirm-Shaming Patterns (Emotional manipulation)
  const confirmShamePhrases = [
    { phrase: 'no thanks, i hate', severity: 'HIGH' as const },
    { phrase: "no, i don't want to save", severity: 'HIGH' as const },
    { phrase: 'no thanks, i prefer paying full', severity: 'HIGH' as const },
    { phrase: "i don't care about my security", severity: 'CRITICAL' as const },
    { phrase: "no, i'd rather miss out", severity: 'HIGH' as const },
    { phrase: 'i hate free', severity: 'MEDIUM' as const },
    { phrase: 'no thanks, i already know everything', severity: 'MEDIUM' as const }
  ];

  for (const item of confirmShamePhrases) {
    if (text.includes(item.phrase)) {
      badges.push({
        id: 'CONFIRM_SHAMING',
        category: 'MANIPULATION',
        severity: item.severity,
        title: 'Confirm-Shaming Trigger',
        description: `Employs manipulative emotional language ("${item.phrase}") to induce guilt and discourage opt-outs.`,
        evidence: item.phrase,
      });
      break;
    }
  }

  // 4. Artificial Urgency / False Scarcity
  const urgencyKeywords = [
    'immediate action required',
    'account will be suspended within 24 hours',
    'terminating your access',
    'offer expires in',
    'last chance to claim',
    'only 1 spot left',
    'urgent response required',
    'final notice',
  ];

  const foundUrgency = urgencyKeywords.filter((k) => text.includes(k));
  if (foundUrgency.length > 0) {
    badges.push({
      id: 'ARTIFICIAL_URGENCY',
      category: 'MANIPULATION',
      severity: 'HIGH',
      title: 'False Urgency / Coercive Countdown',
      description: `Discovered high-pressure psychological triggers (${foundUrgency.slice(0, 2).join(', ')}) designed to bypass critical decision making.`,
    });
  }

  // 5. Unsubscribe Compliance Check
  if (!listUnsubscribeHeader && (text.includes('marketing') || text.includes('newsletter') || text.includes('special offer') || text.includes('unsubscribe'))) {
    // If marketing indicators exist but no List-Unsubscribe header
    badges.push({
      id: 'MISSING_RFC_UNSUBSCRIBE',
      category: 'COMPLIANCE',
      severity: 'MEDIUM',
      title: 'Missing RFC-8058 One-Click Header',
      description: 'Lacks native List-Unsubscribe header mandated by major inbox providers (Google & Yahoo 2024 compliance rules).',
    });
  }

  // Calculate composite risk score
  let score = 0;
  for (const b of badges) {
    switch (b.severity) {
      case 'CRITICAL':
        score += 35;
        break;
      case 'HIGH':
        score += 25;
        break;
      case 'MEDIUM':
        score += 15;
        break;
      case 'LOW':
        score += 5;
        break;
    }
  }

  score = Math.min(score, 100);

  let riskLevel: HeuristicReport['riskLevel'] = 'CLEAN';
  if (score >= 70) riskLevel = 'CRITICAL';
  else if (score >= 45) riskLevel = 'HIGH';
  else if (score >= 25) riskLevel = 'ELEVATED';
  else if (score > 0) riskLevel = 'LOW';

  let summary = 'No overt deceptive heuristics flagged by preliminary client scan.';
  if (badges.length > 0) {
    summary = `Preliminary scan flagged ${badges.length} anomaly indicator(s). Review detailed forensic telemetry below.`;
  }

  return {
    riskScore: score,
    riskLevel,
    badges,
    summary,
  };
}
