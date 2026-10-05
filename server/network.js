import ipaddr from 'ipaddr.js';

export function network(value) {
  if (typeof value !== 'string') throw new Error('IP address or CIDR expected');
  const [address, prefix] = value.includes('/') ? ipaddr.parseCIDR(value) : [ipaddr.parse(value), null];
  const bits = address.kind() === 'ipv4' ? 32 : 128;
  const length = prefix ?? bits;
  const integer = address.toByteArray().reduce((n, byte) => (n << 8n) | BigInt(byte), 0n);
  const hostBits = BigInt(bits - length);
  const start = (integer >> hostBits) << hostBits;
  const end = start + (1n << hostBits) - 1n;
  return { bits, prefix: length, start, end, cidr: `${formatIP(start, bits)}/${length}` };
}

export function tryNetwork(value) { try { return network(value); } catch { return null; } }
export function formatIP(value, bits) {
  const bytes = Array.from({ length: bits / 8 }, (_, i) => Number((value >> BigInt(bits - (i + 1) * 8)) & 255n));
  return ipaddr.fromByteArray(bytes).toString();
}
export function overlaps(a, b) { return a.bits === b.bits && a.start <= b.end && b.start <= a.end; }
export function contains(a, b) { return a.bits === b.bits && a.start <= b.start && a.end >= b.end; }
export function intersection(a, b) {
  if (!overlaps(a, b)) return null;
  return { bits: a.bits, start: a.start > b.start ? a.start : b.start, end: a.end < b.end ? a.end : b.end };
}
export function rangeLabel(r) { return r.start === r.end ? formatIP(r.start, r.bits) : `${formatIP(r.start, r.bits)} – ${formatIP(r.end, r.bits)}`; }
export function subtract(ranges, cuts) {
  for (const cut of cuts) {
    ranges = ranges.flatMap(r => {
      const common = intersection(r, cut);
      if (!common) return [r];
      const result = [];
      if (r.start < common.start) result.push({ ...r, end: common.start - 1n });
      if (common.end < r.end) result.push({ ...r, start: common.end + 1n });
      return result;
    });
  }
  return ranges;
}
