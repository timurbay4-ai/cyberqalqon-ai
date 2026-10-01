/**
 * JsonViewer — safe, read-only JSON display.
 *
 * Security notes:
 * - Uses textContent only (no innerHTML, no dangerouslySetInnerHTML)
 * - Syntax highlighting is applied via className spans on safe text nodes
 * - Content is never eval'd or executed
 * - Large payloads are truncated with a warning
 */

import { useState } from 'react';
import { safeJsonStringify } from '@/utils';

const MAX_CHARS = 50_000; // prevent layout destruction from huge payloads

interface JsonViewerProps {
  data: unknown;
  label?: string;
  initiallyExpanded?: boolean;
}

function highlightJson(json: string): React.ReactNode[] {
  // Safe token-based highlighting — no eval, no innerHTML
  const tokens = json.split(
    /("(?:[^"\\]|\\.)*"(?=\s*:))|("(?:[^"\\]|\\.)*")|(true|false)|(null)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
  );

  return tokens.map((token, i) => {
    if (token == null || token === '') return null;
    if (/^"[^"]*":/.test(token + ':') && !token.endsWith('"')) {
      // key
      return <span key={i} className="json-key">{token}</span>;
    }
    if (/^"/.test(token)) {
      return <span key={i} className="json-string">{token}</span>;
    }
    if (token === 'true' || token === 'false') {
      return <span key={i} className="json-boolean">{token}</span>;
    }
    if (token === 'null') {
      return <span key={i} className="json-null">{token}</span>;
    }
    if (/^-?\d/.test(token)) {
      return <span key={i} className="json-number">{token}</span>;
    }
    return <span key={i}>{token}</span>;
  }).filter(Boolean);
}

export function JsonViewer({ data, label = 'Raw JSON', initiallyExpanded = false }: JsonViewerProps) {
  const [expanded, setExpanded] = useState(initiallyExpanded);

  const raw = safeJsonStringify(data);
  const truncated = raw.length > MAX_CHARS;
  const display = truncated ? raw.slice(0, MAX_CHARS) + '\n\n... [truncated — payload exceeds display limit]' : raw;

  const handleCopy = () => {
    navigator.clipboard.writeText(raw).catch(() => {
      /* clipboard may be unavailable in some browsers */
    });
  };

  return (
    <div className="json-viewer">
      <div className="json-viewer-header">
        <span className="json-viewer-label">{label}</span>
        <div className="flex gap-2">
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={handleCopy}
            aria-label="Copy JSON to clipboard"
            title="Copy to clipboard"
          >
            📋 Copy
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            aria-label={expanded ? 'Collapse JSON' : 'Expand JSON'}
          >
            {expanded ? '▲ Collapse' : '▼ Expand'}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="json-viewer-body" role="region" aria-label={`${label} content`}>
          {truncated && (
            <div className="warning-message mb-4" role="alert">
              ⚠️ Payload is large. Displaying first {MAX_CHARS.toLocaleString()} characters. Use Copy for the full content.
            </div>
          )}
          <pre aria-label="JSON content">{highlightJson(display)}</pre>
        </div>
      )}
    </div>
  );
}
