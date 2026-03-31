// ClawHub Local Skill - runs entirely in your agent, no API key required
// Whois & DNS Lookup - Query DNS records for any domain

import { resolve4, resolve6, resolveMx, resolveTxt, resolveCname, resolveNs } from 'dns/promises';

async function dnsLookup(domain: string) {
  const results: Record<string, any> = {};
  try { results.a = await resolve4(domain); } catch { results.a = []; }
  try { results.aaaa = await resolve6(domain); } catch { results.aaaa = []; }
  try { results.mx = await resolveMx(domain); } catch { results.mx = []; }
  try { results.txt = (await resolveTxt(domain)).map(r => r.join('')); } catch { results.txt = []; }
  try { results.cname = await resolveCname(domain); } catch { results.cname = []; }
  try { results.ns = await resolveNs(domain); } catch { results.ns = []; }
  return results;
}

export async function run(input: { domain: string }) {
  if (!input.domain || typeof input.domain !== 'string') throw new Error('domain is required');
  const clean = input.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/.test(clean)) throw new Error('Invalid domain format');

  const startTime = Date.now();
  const dns = await dnsLookup(clean);

  return {
    domain: clean, dns,
    has_ipv4: dns.a.length > 0, has_ipv6: dns.aaaa.length > 0,
    has_mail: dns.mx.length > 0, nameservers: dns.ns,
    _meta: { skill: 'whois-dns-lookup', latency_ms: Date.now() - startTime },
  };
}

export default run;
