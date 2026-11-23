// GLOBAL campus split routing: campus IPv4 direct, domestic IPv6 direct, public IPv4 via each subscription.
// Preserve subscription nodes, groups, special DNS policies and rule providers; replace ordinary DNS for campus access.
function main(config, profileName) {
  var rules = config.rules || [];
  var match = rules.filter(function(rule) { return rule.indexOf('MATCH,') === 0; }).pop();
  if (!match) throw new Error('A subscription MATCH proxy group is required.');
  var proxyGroup = match.split(',')[1];
  if (proxyGroup === 'DIRECT' || proxyGroup.indexOf('REJECT') === 0) {
    throw new Error('The default route must use a real proxy group.');
  }

  // Rule mode, global IPv6 and TUN remain controlled by the application settings.
  var dns = config.dns || (config.dns = {});
  dns.enable = true;
  dns.ipv6 = true;
  dns['enhanced-mode'] = 'redir-host';
  // Use a reachable IPv6 DoH endpoint, with certificate DNS-name verification enabled.
  // Avoid the subscriptions' unreachable IPv4 bootstrap/fallback DNS on this campus network.
  dns.nameserver = ['https://[2400:3200:baba::1]/dns-query#name-cert-verify=dns.alidns.com'];
  dns['default-nameserver'] = ['system', '2400:3200::1'];
  dns.fallback = [];
  dns['respect-rules'] = false;
  dns['nameserver-policy'] = Object.assign({}, dns['nameserver-policy'] || {}, {
    '+.bjut.edu.cn': ['172.21.0.21', '172.21.201.22']
  });
  dns['direct-nameserver-follow-policy'] = true;

  // Sniffing may identify a domain for rules but must not discard the actual destination IP.
  if (config.sniffer) {
    config.sniffer['override-destination'] = false;
    var protocols = config.sniffer.sniff || {};
    Object.keys(protocols).forEach(function(key) {
      if (protocols[key] && typeof protocols[key] === 'object' && !Array.isArray(protocols[key])) {
        protocols[key]['override-destination'] = false;
      }
    });
  }

  var directName = 'IPv6直连';
  var proxies = config.proxies || (config.proxies = []);
  var existing = proxies.filter(function(proxy) { return proxy.name === directName; });
  if (existing.length > 1 || (existing.length && existing[0].type !== 'direct')) {
    throw new Error('The IPv6 direct exit name conflicts with an existing proxy.');
  }
  if (!existing.length) proxies.push({name: directName, type: 'direct', 'ip-version': 'ipv6'});
  else existing[0]['ip-version'] = 'ipv6';

  var privateRanges = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24',
    '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '224.0.0.0/3', '::/127', 'fc00::/7', 'fe80::/10', 'ff00::/8'
  ];
  var prefix = ['DOMAIN-SUFFIX,bjut.edu.cn,DIRECT'];
  privateRanges.forEach(function(cidr) {
    prefix.push('IP-CIDR,' + cidr + ',DIRECT,no-resolve');
  });
  if (config['rule-providers'] && config['rule-providers'].private_domain) {
    prefix.push('RULE-SET,private_domain,DIRECT,no-resolve');
  }
  // Preserve explicit domain/IP blocking. Leave protocol-specific blocks in their old relative order.
  var blockers = rules.filter(function(rule) {
    var parts = rule.split(',');
    var policy = parts[parts.length - 1] === 'no-resolve' ? parts[parts.length - 2] : parts[parts.length - 1];
    return /^(DOMAIN(?:-[A-Z]+)?|GEOSITE|RULE-SET|IP-CIDR6?|IP-ASN),/.test(rule) && /^REJECT(?:-DROP)?$/.test(policy);
  });
  var domesticV6 = 'AND,((IP-CIDR6,::/0,no-resolve),(GEOIP,CN,no-resolve)),' + directName;
  var publicV4 = 'IP-CIDR,0.0.0.0/0,' + proxyGroup + ',no-resolve';
  var owned = prefix.concat(blockers, [domesticV6, publicV4]);
  var ownedSet = Object.create(null);
  owned.forEach(function(rule) { ownedSet[rule] = true; });
  var rest = rules.filter(function(rule) {
    return !ownedSet[rule] && rule.indexOf('MATCH,') !== 0;
  });
  config.rules = prefix.concat(blockers, [domesticV6, publicV4], rest, ['MATCH,' + proxyGroup]);
  return config;
}
