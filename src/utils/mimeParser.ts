/**
 * GhostProtocol Client-Side RFC 5322 MIME & .eml File Parser
 * Runs 100% locally in browser memory without external server transmissions.
 */

export interface ParsedEmail {
  subject: string;
  from: string;
  to: string;
  date: string;
  listUnsubscribe: string | null;
  messageId: string | null;
  cleanBody: string;
  rawHtml: string | null;
  headers: Record<string, string>;
  isMimeParsed: boolean;
}

/**
 * Decodes RFC 2047 encoded words (=?UTF-8?B?...?= or =?UTF-8?Q?...?=)
 */
function decodeRfc2047(text: string): string {
  if (!text || !text.includes('=?')) return text;

  const encodedWordRegex = /=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g;
  return text.replace(encodedWordRegex, (_: string, charset: string, encoding: string, data: string) => {
    try {
      const isBase64 = encoding.toUpperCase() === 'B';
      if (isBase64) {
        const binary = atob(data.replace(/\s+/g, ''));
        const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
        return new TextDecoder(charset || 'utf-8').decode(bytes);
      } else {
        // Quoted-Printable in header
        const unescaped = data
          .replace(/_/g, ' ')
          .replace(/=([A-Fa-f0-9]{2})/g, (_: string, hex: string) => String.fromCharCode(parseInt(hex, 16)));
        return unescaped;
      }
    } catch {
      return data;
    }
  });
}

/**
 * Decodes Quoted-Printable email body content
 */
function decodeQuotedPrintable(input: string): string {
  return input
    // Soft line breaks
    .replace(/=\r?\n/g, '')
    // Hex escape sequences
    .replace(/=([A-Fa-f0-9]{2})/g, (_: string, hex: string) => {
      const code = parseInt(hex, 16);
      return String.fromCharCode(code);
    });
}

/**
 * Strips HTML tags while preserving line breaks and links for plain text readability
 */
function convertHtmlToPlainText(html: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');

  // Convert break tags and paragraph ends to newlines
  doc.querySelectorAll('br').forEach((el) => el.replaceWith('\n'));
  doc.querySelectorAll('p, div, h1, h2, h3, h4, tr, li').forEach((el) => {
    el.prepend('\n');
    el.append('\n');
  });

  // Preserve link anchors: [text](href)
  doc.querySelectorAll('a').forEach((link) => {
    const href = link.getAttribute('href');
    const text = link.textContent?.trim();
    if (href && text && !href.startsWith('mailto:')) {
      link.textContent = `${text} [Link: ${href}]`;
    }
  });

  const rawText = doc.body.textContent || '';
  return rawText
    .replace(/\n\s*\n\s*\n/g, '\n\n')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

/**
 * Parses raw .eml or raw pasted email text into clean headers and plain text body.
 */
export function parseRawEmail(rawContent: string): ParsedEmail {
  // Normalize line breaks
  const normalized = rawContent.replace(/\r\n/g, '\n');

  // Check if content looks like RFC 5322 with headers
  const splitIndex = normalized.search(/\n\n/);
  
  // If there's no double newline or no typical header keywords, treat as raw email body dump
  if (splitIndex === -1 || !normalized.slice(0, splitIndex).match(/^(from|to|subject|date|received|content-type):/im)) {
    return {
      subject: '(Direct Text Input)',
      from: 'Unknown Sender',
      to: 'Recipient',
      date: new Date().toISOString(),
      listUnsubscribe: null,
      messageId: null,
      cleanBody: rawContent.trim(),
      rawHtml: null,
      headers: {},
      isMimeParsed: false,
    };
  }

  const headerBlock = normalized.slice(0, splitIndex);
  let bodyBlock = normalized.slice(splitIndex + 2);

  // Parse RFC 5322 headers handling folded lines (continuation lines starting with space or tab)
  const headerLines = headerBlock.split('\n');
  const headers: Record<string, string> = {};
  let currentKey = '';

  for (const line of headerLines) {
    if (/^[ \t]/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
    } else {
      const match = line.match(/^([\w-]+):\s*(.*)$/);
      if (match) {
        currentKey = match[1].toLowerCase();
        headers[currentKey] = match[2].trim();
      }
    }
  }

  const subject = decodeRfc2047(headers['subject'] || '(No Subject Specified)');
  const from = decodeRfc2047(headers['from'] || 'Unknown Sender');
  const to = decodeRfc2047(headers['to'] || 'Confidential Recipient');
  const date = headers['date'] || new Date().toISOString();
  const listUnsubscribe = headers['list-unsubscribe'] || null;
  const messageId = headers['message-id'] || null;
  const contentType = headers['content-type'] || 'text/plain';

  let rawHtml: string | null = null;
  let cleanBody = '';

  // Handle Multipart messages
  const boundaryMatch = contentType.match(/boundary=["']?([^"';]+)["']?/i);
  if (boundaryMatch) {
    const boundary = boundaryMatch[1];
    const parts = bodyBlock.split(new RegExp(`--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));

    let plainPart = '';
    let htmlPart = '';

    for (const part of parts) {
      if (part.includes('--') && part.trim() === '--') continue;

      const partSplit = part.search(/\n\n/);
      if (partSplit !== -1) {
        const partHeaders = part.slice(0, partSplit).toLowerCase();
        let partBody = part.slice(partSplit + 2);

        // Decode part encoding
        if (partHeaders.includes('content-transfer-encoding: quoted-printable')) {
          partBody = decodeQuotedPrintable(partBody);
        } else if (partHeaders.includes('content-transfer-encoding: base64')) {
          try {
            partBody = atob(partBody.replace(/\s+/g, ''));
          } catch {
            // Keep as is if corrupted
          }
        }

        if (partHeaders.includes('text/plain') && !plainPart) {
          plainPart = partBody.trim();
        } else if (partHeaders.includes('text/html') && !htmlPart) {
          htmlPart = partBody.trim();
        }
      }
    }

    if (plainPart) {
      cleanBody = plainPart;
      rawHtml = htmlPart || null;
    } else if (htmlPart) {
      rawHtml = htmlPart;
      cleanBody = convertHtmlToPlainText(htmlPart);
    }
  }

  // Fallback if not multipart
  if (!cleanBody) {
    const transferEncoding = (headers['content-transfer-encoding'] || '').toLowerCase();
    if (transferEncoding === 'quoted-printable') {
      bodyBlock = decodeQuotedPrintable(bodyBlock);
    } else if (transferEncoding === 'base64') {
      try {
        bodyBlock = atob(bodyBlock.replace(/\s+/g, ''));
      } catch {
        // Fallback
      }
    }

    if (contentType.toLowerCase().includes('text/html') || bodyBlock.includes('<html') || bodyBlock.includes('<body') || bodyBlock.includes('<div')) {
      rawHtml = bodyBlock;
      cleanBody = convertHtmlToPlainText(bodyBlock);
    } else {
      cleanBody = bodyBlock.trim();
    }
  }

  return {
    subject,
    from,
    to,
    date,
    listUnsubscribe,
    messageId,
    cleanBody,
    rawHtml,
    headers,
    isMimeParsed: true,
  };
}
