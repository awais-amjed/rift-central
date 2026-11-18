/**
 * Whether [url] names its host the one way central's directory can compare.
 *
 * A listing is one per `server_url_key` (central's migrations): the address's
 * scheme and host, lower-cased, without the default port, a trailing dot or a
 * path. The listing proof is asked of the host's root, so every spelling that
 * reaches the same machine verifies — and a URL parser reaches it from more
 * spellings than that key can see: percent-escapes in the host
 * (`sr%76.example.com`), Unicode for its punycode, a port with leading zeros.
 * Each would be a second listing for one server, which is how a moderator's
 * hide was undone. So the host is refused unless it is spelled in plain ASCII
 * letters, digits, dots and hyphens, with a port written plainly if at all.
 */
export function isPlainAddress(url: string): boolean {
  return /^https:\/\/[A-Za-z0-9.-]+(:[1-9][0-9]{0,4})?(\/[^?#]*)?$/.test(url);
}
