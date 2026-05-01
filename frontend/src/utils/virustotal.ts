/**
 * VirusTotal URL helpers.
 *
 * VT GUI URL format for a scanned URL:
 *   https://www.virustotal.com/gui/url/{url_id}
 * where url_id = base64url(url) with padding stripped.
 *
 * VT GUI URL format for a file hash:
 *   https://www.virustotal.com/gui/file/{sha256}
 */

/**
 * Generate the correct VirusTotal GUI link for a given URL.
 * VT URL ID = base64url(url) with '=' padding stripped.
 */
export function getVtUrlLink(url: string): string {
  try {
    // btoa → base64, then convert to base64url and strip padding
    const base64 = btoa(url)
      .replace(/\+/g, '-')  // + → -
      .replace(/\//g, '_')  // / → _
      .replace(/=+$/, '');  // strip padding
    return `https://www.virustotal.com/gui/url/${base64}`;
  } catch {
    // Fallback for URLs containing non-ASCII characters
    try {
      const encoded = btoa(unescape(encodeURIComponent(url)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      return `https://www.virustotal.com/gui/url/${encoded}`;
    } catch {
      // Last-resort: just return the VT search page
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`;
    }
  }
}

/**
 * Generate the correct VirusTotal GUI link for a file SHA-256 hash.
 */
export function getVtFileLink(sha256: string): string {
  return `https://www.virustotal.com/gui/file/${sha256}`;
}
