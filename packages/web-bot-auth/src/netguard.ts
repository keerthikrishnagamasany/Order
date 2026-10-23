/**
 * Network guards for fetching agent key directories.
 *
 * The Signature-Agent header is attacker-controlled. If a verifier fetched whatever it
 * named, an attacker could make your server request internal addresses (cloud metadata,
 * admin panels, localhost services) — server-side request forgery. The draft says
 * verifiers SHOULD refuse private, loopback and link-local destinations (Sec. 6.7).
 *
 * The check runs inside the DNS lookup used for the actual connection (see
 * `guardedLookup`), not as a separate pre-check, so a hostname can't pass the check and
 * then resolve to a private address at connect time (DNS rebinding).
 */

import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { isIP } from "node:net";

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function inV4(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.split("/") as [string, string];
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}

const BLOCKED_V4 = [
  "0.0.0.0/8", // "this" network
  "10.0.0.0/8", // private
  "100.64.0.0/10", // carrier-grade NAT
  "127.0.0.0/8", // loopback
  "169.254.0.0/16", // link-local (incl. cloud metadata 169.254.169.254)
  "172.16.0.0/12", // private
  "192.0.0.0/24", // IETF protocol assignments
  "192.0.2.0/24", // documentation
  "192.168.0.0/16", // private
  "198.18.0.0/15", // benchmarking
  "198.51.100.0/24", // documentation
  "203.0.113.0/24", // documentation
  "224.0.0.0/4", // multicast
  "240.0.0.0/4", // reserved, incl. broadcast
];

/**
 * Expand any valid IPv6 text form (`::`, embedded dotted IPv4, hex IPv4 tails) into
 * exactly eight 16-bit groups. Notation must never change the verdict — e.g. the URL
 * parser rewrites `::ffff:127.0.0.1` as `::ffff:7f00:1`.
 */
function expandV6(addr: string): number[] | null {
  let a = addr.toLowerCase();
  const pct = a.indexOf("%");
  if (pct >= 0) a = a.slice(0, pct); // drop zone id
  // Embedded dotted IPv4 tail -> two hex groups.
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (dotted) {
    const v4 = dotted[1] as string;
    if (isIP(v4) !== 4) return null;
    const n = v4ToInt(v4);
    a = a.slice(0, -v4.length) + `${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = a.split("::");
  if (halves.length > 2) return null;
  const parse = (s: string) => (s === "" ? [] : s.split(":").map((g) => parseInt(g, 16)));
  const head = parse(halves[0] as string);
  const tail = halves.length === 2 ? parse(halves[1] as string) : [];
  const groups = halves.length === 2 ? [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail] : head;
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g) || g < 0 || g > 0xffff)) return null;
  return groups;
}

/** True for any address a key-directory fetch must never reach. */
export function isPrivateAddress(address: string): boolean {
  const raw = address.replace(/^\[|\]$/g, "");
  const family = isIP(raw);
  if (family === 4) return BLOCKED_V4.some((c) => inV4(raw, c));
  if (family === 6) {
    const g = expandV6(raw);
    if (!g) return true; // unparseable: refuse
    const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [number, number, number, number, number, number, number, number];
    const v4Tail = `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
    const zeroHead = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
    if (zeroHead && g5 === 0 && g6 === 0 && (g7 === 0 || g7 === 1)) return true; // :: and ::1
    if (zeroHead && g5 === 0xffff) return isPrivateAddress(v4Tail); // ::ffff:0:0/96 IPv4-mapped
    if (zeroHead && g5 === 0) return isPrivateAddress(v4Tail); // ::/96 IPv4-compatible (deprecated)
    if (g0 === 0x64 && g1 === 0xff9b) return true; // 64:ff9b::/96 NAT64 — may front internal v4
    if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
    if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast
    if (g0 === 0x2001 && g1 === 0x0db8) return true; // 2001:db8::/32 documentation
    return false;
  }
  return true; // not an IP at all: refuse rather than guess
}

export type LookupFn = (
  hostname: string,
  options: { all: true; family?: number },
  cb: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void;

/**
 * A `lookup` for `https.request` that resolves the host and refuses the connection if ANY
 * resolved address is private. Supports both callback shapes Node uses (`all` or single).
 */
export function guardedLookup(resolve: LookupFn = dnsLookup as unknown as LookupFn) {
  return (
    hostname: string,
    options: { all?: boolean; family?: number } | number,
    cb: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
  ): void => {
    const opts = typeof options === "number" ? { family: options } : options;
    resolve(hostname, { all: true, ...(opts.family ? { family: opts.family } : {}) }, (err, addresses) => {
      if (err) return cb(err, "");
      if (addresses.length === 0) return cb(Object.assign(new Error("no addresses"), { code: "ENOTFOUND" }), "");
      const bad = addresses.find((a) => isPrivateAddress(a.address));
      if (bad) {
        return cb(
          Object.assign(new Error(`refusing to connect to non-public address ${bad.address}`), { code: "EPRIVATE" }),
          "",
        );
      }
      if (opts.all) return cb(null, addresses);
      const first = addresses[0] as LookupAddress;
      return cb(null, first.address, first.family);
    });
  };
}

/** Strict origin check: `https://host[:port]` exactly, as the draft requires. */
export function isHttpsOrigin(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !u.username && !u.password && value === u.origin;
  } catch {
    return false;
  }
}
