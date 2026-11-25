export default async function securityHeaders(request: Request, context: { next: () => Promise<Response> }) {
  const response = await context.next();
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('text/html')) return response;

  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  const nonce = btoa(String.fromCharCode(...bytes));
  const html = await response.text();
  const securedHtml = html.replace(/<script\b(?![^>]*\bnonce\s*=)([^>]*)>/gi, `<script nonce="${nonce}"$1>`);
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete('content-encoding');
  headers.delete('etag');
  headers.set('content-security-policy', [
    "default-src 'self'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    'upgrade-insecure-requests',
  ].join('; '));
  headers.set('x-content-type-options', 'nosniff');
  headers.set('referrer-policy', 'strict-origin-when-cross-origin');
  headers.set('x-frame-options', 'DENY');
  return new Response(securedHtml, { status: response.status, statusText: response.statusText, headers });
}
