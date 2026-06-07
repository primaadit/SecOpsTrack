/**
 * SecOpsTrack — Red vs Blue CTF Lab | by SalimLabs
 * Author  : Prima Praditya | github.com/primaadit/SecOpsTrack
 * ⚠  Intentionally vulnerable — isolated environments only
 */
const fs = require('fs');

// ============================================================
// Rudimentary WAF Middleware
// FLAGS:
//   SALIMLABS{POST}         - feedback only via POST
//   SALIMLABS{403}          - blocks <script> with 403
//   SALIMLABS{<svg>}        - bypassable via <svg onload=...>
//   SALIMLABS{window['docu'+'ment']['coo'+'kie']} - cookie obfuscation bypass
//   SALIMLABS{fetch}        - fetch API allowed for exfiltration
// ============================================================

const BLOCKED_PATTERNS = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript:/i,
  /document\.cookie/i,
  /onmouseover\s*=/i,
  /eval\s*\(/i,
];

// INTENTIONALLY NOT BLOCKED (WAF bypass vectors):
// - <svg onload=...>
// - window['docu'+'ment']['coo'+'kie']  (bracket notation obfuscation)
// - fetch()

function logWafBlock(payload, ip, timestamp) {
  const logPath = '/opt/admin/logs/error.log';
  const entry = `${timestamp} [ERROR] WAF_BLOCK - IP: ${ip} - Blocked payload detected: ${payload.substring(0, 120)}
`;
  try {
    fs.appendFileSync(logPath, entry);
  } catch (e) {
    // silently fail if log dir not yet mounted
  }
}

function wafMiddleware(req, res, next) {
  if (req.method === 'POST' && (req.path === '/feedback' || req.path === '/api/feedback')) {
    const body = JSON.stringify(req.body);
    for (const pattern of BLOCKED_PATTERNS) {
      if (pattern.test(body)) {
        const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
        logWafBlock(body, req.ip, ts);
        return res.status(403).json({
          error: 'WAF: Forbidden - Malicious payload detected',
          code: 403,
          blocked: true,
          hint: 'Try a different approach...'
        });
      }
    }
  }
  next();
}

module.exports = wafMiddleware;
