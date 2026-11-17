// BJUT: real DNS answers + destination-IP routing in TUN mode.
// Campus/private destinations DIRECT; restricted domains PROXY;
// real IPv6 destinations DIRECT; remaining public IPv4 destinations PROXY.
function main(config, profileName) {
  const legacyDirect6 = 'IPv6直连';
  const originalRules = config.rules || [];
  const groups = config['proxy-groups'] || [];
  const match = originalRules.find(rule => rule.startsWith('MATCH,') && !['DIRECT', 'REJECT'].includes(rule.split(',')[1]));
  const proxy = match ? match.split(',')[1] : (groups.find(group => !['DIRECT', legacyDirect6].includes(group.name)) || {}).name;
  if (!proxy) throw new Error('No subscription proxy group found.');
  config.ipv6 = true;
  config.proxies = (config.proxies || []).filter(node => node.name !== legacyDirect6);
  // A ULA source on Windows TUN can make RFC 6724 sorting favor IPv4.
  // Use the reserved IPv6 benchmarking prefix on this virtual interface;
  // the actual external connection still uses the physical campus interface.
  config.tun = Object.assign({}, config.tun || {}, {'inet6-address': ['2001:2::1/126']});

  const campusRules = [
    'DOMAIN-SUFFIX,bjut.edu.cn,DIRECT',
    'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve',
    'IP-CIDR6,::1/128,DIRECT,no-resolve',
    'IP-CIDR6,fc00::/7,DIRECT,no-resolve',
    'IP-CIDR6,fe80::/10,DIRECT,no-resolve'
  ];
  const automaticIPv6 = 'IP-CIDR6,::/0,DIRECT,no-resolve';
  const restrictedDomains = 'GEOSITE,gfw,' + proxy;
  // Domains with unusable campus DNS answers or blocked direct access.
  // Keep these exceptions before the general IPv6 DIRECT rule.
  const forcedProxyDomains = ['agentrouter.org', 'anyrouter.top'];
  const forcedProxyRules = forcedProxyDomains.map(domain => 'DOMAIN-SUFFIX,' + domain + ',' + proxy);
  const isLocal = parts => {
    const privateRuleSet = parts[0] === 'RULE-SET' && /^(private|lan)(_|$)/i.test(parts[1]);
    const reservedIP = /^IP-CIDR6?$/.test(parts[0]) && /^(0\.0\.0\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|100\.64\.|192\.0\.[02]\.|192\.88\.99\.|198\.18\.|198\.51\.100\.|203\.0\.113\.|224\.|fc00:|fe80:|ff00:|::\/127)/i.test(parts[1]);
    const localDomain = parts[0] === 'DOMAIN' && ['injections.adguard.org','local.adguard.org'].includes(parts[1]);
    return privateRuleSet || reservedIP || localDomain;
  };
  const localRules = [], rejectRules = [], publicRules = [];
  for (const rule of originalRules) {
    if (rule.startsWith('MATCH,') || campusRules.includes(rule) || rule.endsWith(',' + legacyDirect6) || rule === automaticIPv6 || rule.startsWith('GEOSITE,gfw,') || forcedProxyDomains.some(domain => rule.startsWith('DOMAIN-SUFFIX,' + domain + ','))) continue;
    const parts = rule.split(',');
    if (parts[2] === 'DIRECT' && isLocal(parts)) {
      localRules.push(rule);
    } else if (parts[2] === 'REJECT' && parts[0] !== 'AND') {
      rejectRules.push(rule);
    } else {
      if (parts[2] === 'DIRECT') parts[2] = proxy;
      // Existing public domain rules are placed AFTER automatic IPv6 routing.
      // The subscription's UDP/443 rejection likewise only applies after it.
      publicRules.push(parts.join(','));
    }
  }
  config.rules = [...new Set(campusRules.concat(localRules, rejectRules,
    forcedProxyRules, [restrictedDomains, automaticIPv6], publicRules, ['MATCH,' + proxy]))];

  const dns = config.dns || {};
  dns.enable = true;
  dns.ipv6 = true;
  dns['enhanced-mode'] = 'redir-host';
  // This campus resolver supplies working CERNET IPv6 CDN answers.
  dns.nameserver = ['172.21.201.22#DIRECT'];
  dns['default-nameserver'] = ['172.21.201.22', '172.21.0.21'];
  dns['direct-nameserver'] = ['172.21.201.22#DIRECT'];
  dns['direct-nameserver-follow-policy'] = true;
  dns.fallback = [];
  const policy = Object.assign({}, dns['nameserver-policy'] || {});
  const legacyBiliDomains = ['www.bilibili.com','api.bilibili.com','passport.bilibili.com','s1.hdslb.com','i0.hdslb.com','upos-sz-mirrorali.bilivideo.com','upos-sz-mirrorhw.bilivideo.com','cn-bj-se-01-03.bilivideo.com','upos-sz-estgoss.bilivideo.com'];
  for (const domain of legacyBiliDomains) {
    if (JSON.stringify(policy[domain]) === JSON.stringify(['172.21.201.22#DIRECT'])) delete policy[domain];
  }
  policy['+.bjut.edu.cn'] = ['172.21.201.22#DIRECT', '172.21.0.21#DIRECT'];
  // Route this DoH resolver through the subscription group as well.
  // A literal resolver IP avoids bootstrap dependence on campus DNS.
  for (const domain of forcedProxyDomains) {
    policy['+.' + domain] = ['https://1.1.1.1/dns-query#' + proxy];
  }
  dns['nameserver-policy'] = policy;
  for (const key of ['fake-ip-range','fake-ip-range6','fake-ip-filter','fake-ip-filter-mode','fake-ip-ttl']) delete dns[key];
  config.dns = dns;
  // Preserve the real destination IP when any pre-existing sniffer is enabled.
  if (config.sniffer) config.sniffer['override-destination'] = false;
  return config;
}
