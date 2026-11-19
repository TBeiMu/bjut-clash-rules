// Campus, Bilibili and verified Douyin/QQ/WeChat IPv6 routing.
// Original subscription nodes are kept; only DNS and final routing are enhanced.
function main(config, profileName) {
  const directName = "IPv6直连";
  const campusDNS = ["172.21.201.21#DIRECT", "172.21.201.20#DIRECT"];
  const campusDomains = ["bjut.edu.cn", "bjpu.edu.cn"];
  // Representative web/API/image/CDN hosts in these families were tested locally.
  const ipv6Domains = [
    "bilibili.com", "biliapi.com", "biliapi.net",
    "bilivideo.com", "hdslb.com", "biliimg.com", "bilicdn1.com", "steamcontent.com"
  ];
  // Exact hosts with verified IPv6 HTTPS connectivity (2026-11-16).
  // Keep untested siblings on the existing proxy fallback.
  const ipv6ExactDomains = [
      // Additional exact-host trials verified over IPv6 on 2026-11-17.
      // Root-path reachability only; actual resources remain a user-side trial.
      "a.nel.cloudflare.com",
      "appcfg.v.qq.com",
      "aps.amap.com",
      "cdn.exp.xiaomi.com",
      "configsvr.msf.3g.qq.com",
      "findermp.video.qq.com",
      "h.trace.qq.com",
      "meteorology.caiyuncdn.com",
      "mifi-mp-fds.help.jr.mi.com",
      "p3-sign.douyinpic.com",
      "p3-webcast.douyinpic.com",
      "p3.douyinpic.com",
      "pfga-accelerate.market.xiaomi.com",
      "upos-hz-mirrorakam.akamaized.net",
      "xingchiapi.com",
      // PS5 download trial: IPv6 only; no airport fallback (2026-11-17).
      "gst.prod.dl.playstation.net",
      "www.douyin.com",
      "p3-pc.douyinpic.com",
      "p3-pc-sign.douyinpic.com",
      "lf-douyin-pc-web.douyinstatic.com",
      "v26-web.douyinvod.com",
      // Exact video-host trials: IPv6 TLS verified; playback requires observation (2026-11-17).
      "v11-weba.douyinvod.com",
      "pull-flv-l1.douyincdn.com",
      "gchat.qpic.cn",
      "c2cpicdw.qpic.cn",
      // Exact-host trial: network/TLS reachable; business resource not verified (2026-11-19).
      "mpvideo.qpic.cn",
      "wximg.wxs.qq.com",
      "q1.qlogo.cn",
      "q2.qlogo.cn",
      "q4.qlogo.cn",
      "thirdqq.qlogo.cn",
      "ssl.ptlogin2.qq.com",
      "ui.ptlogin2.qq.com",
      "im.qq.com",
      "shortcloud.weixin.com",
      "wx.qlogo.cn",
      "mmbiz.qlogo.cn",
      "weixin.qq.com",
      "mp.weixin.qq.com",
      "wx.qq.com",
      "dldir1v6.qq.com",
      "multimedia.nt.qq.com.cn",
      "res.wxqcloud.qq.com.cn",
      "mcs.zijieapi.com",
      "client-update.akamai.steamstatic.com",
  ];
  const ipv4Exceptions = ["broadcast.chat.bilibili.com"];

  const originalRules = Array.isArray(config.rules) ? config.rules : [];
  const groups = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const nodes = Array.isArray(config.proxies) ? config.proxies : [];
  const nodeNames = nodes.filter(function(p) { return p.type !== "direct"; })
    .map(function(p) { return p.name; });
  // Use the primary real-node selector, not a catch-all selector that offers DIRECT.
  const primary = groups.filter(function(g) {
    if (g.type !== "select" || g.name === directName) return false;
    const choices = Array.isArray(g.proxies) ? g.proxies : [];
    return choices.indexOf("DIRECT") === -1 && (
      choices.some(function(n) { return nodeNames.indexOf(n) !== -1; }) ||
      g["include-all"] || g["include-all-proxies"] ||
      (Array.isArray(g.use) && g.use.length > 0)
    );
  })[0];
  if (!primary) throw new Error("No safe primary proxy selector found; refusing public DIRECT fallback.");
  const proxyName = primary.name;

  config.ipv6 = true;
  config.dns = config.dns || {};
  const dns = config.dns;
  dns.ipv6 = true;
  dns["nameserver-policy"] = Object.assign({}, dns["nameserver-policy"] || {});
  campusDomains.concat(ipv6Domains).forEach(function(domain) {
    dns["nameserver-policy"]["+." + domain] = campusDNS.slice();
  });
  ipv6ExactDomains.forEach(function(host) {
    dns["nameserver-policy"][host] = campusDNS.slice();
  });
  dns["direct-nameserver-follow-policy"] = true;
  if (!dns["fake-ip-filter-mode"] || dns["fake-ip-filter-mode"] === "blacklist") {
    const filters = Array.isArray(dns["fake-ip-filter"]) ? dns["fake-ip-filter"].slice() : [];
    campusDomains.forEach(function(domain) {
      const item = "+." + domain;
      if (filters.indexOf(item) === -1) filters.push(item);
    });
    dns["fake-ip-filter"] = filters;
  }

  if (nodes.some(function(p) { return p.name === directName && p.type !== "direct"; })) {
    throw new Error("Existing non-direct node uses reserved IPv6 direct name.");
  }
  config.proxies = nodes.filter(function(p) { return p.name !== directName; });
  config.proxies.push({ name: directName, type: "direct", "ip-version": "ipv6", udp: true });
  // Keep the direct adapter out of any automatically populated airport group.
  groups.forEach(function(g) {
    if (g["include-all"] || g["include-all-proxies"]) {
      const old = g["exclude-filter"];
      const own = "^" + directName + "$";
      if (!old) g["exclude-filter"] = own;
      else if (old.indexOf(own) === -1) g["exclude-filter"] = "(" + old + ")|" + own;
    }
  });

  const rules = [];
  campusDomains.forEach(function(d) { rules.push("DOMAIN-SUFFIX," + d + ",DIRECT"); });
  [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve"
  ].forEach(function(r) { rules.push(r); });
  // Retain the subscription's private-domain ruleset where present.
  originalRules.forEach(function(r) {
    if (/^RULE-SET,private_domain,DIRECT(?:,|$)/.test(r) && rules.indexOf(r) === -1) rules.push(r);
  });
  ipv4Exceptions.forEach(function(d) { rules.push("DOMAIN," + d + "," + proxyName); });
  
  rules.push("DOMAIN-SUFFIX,agentrouter.org,加拿大-IPv6");
  rules.push("DOMAIN-SUFFIX,ps.air-outer.com,加拿大-IPv6");
  rules.push("DOMAIN-SUFFIX,chatgpt.com,加拿大-IPv6");
  ipv6Domains.forEach(function(d) { rules.push("DOMAIN-SUFFIX," + d + "," + directName); });
  ipv6ExactDomains.forEach(function(d) { rules.push("DOMAIN," + d + "," + directName); });
  // Retain explicit blocking rules; remove public/China DIRECT rules that fail on IPv4.
  originalRules.forEach(function(r) {
    if (/,(REJECT|REJECT-DROP|REJECT-NO-DROP)(?:,no-resolve)?$/.test(r) && rules.indexOf(r) === -1) rules.push(r);
  });
  rules.push("MATCH," + proxyName);
  config.rules = rules;
  return config;
}
