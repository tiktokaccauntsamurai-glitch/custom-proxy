use super::*;
use std::collections::HashMap;

struct Mem(HashMap<String, String>);

impl Resources for Mem {
    fn text(&self, url: &str) -> Option<String> {
        self.0.get(url).cloned()
    }
    fn path(&self, url: &str) -> Option<String> {
        self.0.get(url).cloned()
    }
}

const CONF: &str = r#"[General]
dns-server = https://dns.google/dns-query#proxy=HK%201, 1.1.1.1
ipv6 = false

[Proxy]
HK 1 = trojan, hk.example.com, 443, password=pw, peer=hk.example.com, allowInsecure=1
JP 1 = vless, 1.2.3.4, 443, password=11111111-1111-1111-1111-111111111111, tls=true, obfs=websocket, path=/ws, obfs-host=cdn.example.com
JP R = vless, 1.2.3.5, 443, password=11111111-1111-1111-1111-111111111111, xtls=2, peer=www.apple.com, pbk=Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON-GwPq7SOV4, sid=abcd
SS = ss, 5.6.7.8, 8388, method=aes-256-gcm, password=pw
HY = hysteria2, 9.9.9.9, 443, auth=pw, obfsParam=ob, peer=hy.example.com
TU = tuic, 9.9.9.8, 443, user=11111111-1111-1111-1111-111111111111, password=pw
H = http, 10.0.0.1, 8080, user, pass
WG = wireguard, 2.2.2.2, 51820, privateKey=YNXtAzepDqRv9H52osJVDQnznT5AL11eVbvjmyLnU0U=, publicKey=Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=, ip=10.0.0.2, reserved=1/2/3
SN = snell, 3.3.3.3, 443, password=pw
S4 = snell, 4.4.4.4, 443, psk=pw, version=4, obfs=http, obfs-host=bing.com

[Proxy Group]
Japan = url-test, url=http://www.gstatic.com/generate_204, interval=600, tolerance=50, policy-regex-filter=(?=.*(JP))^.*$
Media = select, DIRECT, Japan, HK 1, policy-select-name=Japan
Ghost = select, SN
Slow = url-test, HK 1, interval=3600

[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT-TINYGIF
DOMAIN,exact.example.com,REJECT-DROP
DOMAIN-WILDCARD,a*c.example?.com,Media
AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP
NOT,((DST-PORT,80)),Ghost
USER-AGENT,Telegram*,PROXY
RULE-SET,https://lists.test/media.list,Media
DOMAIN-SET,https://lists.test/ads.txt,REJECT
GEOIP,CN,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
IP-CIDR,8.8.8.8/32,PROXY
FINAL,PROXY

[Host]
localhost = 127.0.0.1
*.apple.com = server:system

[MITM]
hostname = *.example.com
"#;

fn resources() -> Mem {
    Mem(HashMap::from([
        (
            "https://lists.test/media.list".into(),
            "# media\nDOMAIN-SUFFIX,youtube.com\nDOMAIN,netflix.com\nIP-CIDR,1.0.0.0/24,no-resolve\nUSER-AGENT,Foo*\n".into(),
        ),
        ("https://lists.test/ads.txt".into(), ".doubleclick.net\nads.example.org\n".into()),
        (geoip_url("CN"), "geoip-cn.srs".into()),
    ]))
}

fn generate_sample() -> Output {
    generate(&fmt_shadowrocket::parse(CONF), &resources(), &Options::default()).unwrap()
}

fn find<'a>(arr: &'a Value, tag: &str) -> &'a Value {
    arr.as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap_or_else(|| panic!("no `{tag}`"))
}

#[test]
fn nodes() {
    let out = generate_sample();
    let ob = &out.config["outbounds"];
    let hk = find(ob, "HK 1");
    assert_eq!(hk["tls"]["server_name"], "hk.example.com");
    assert_eq!(hk["tls"]["insecure"], true);
    let jp = find(ob, "JP 1");
    assert_eq!(jp["transport"], json!({"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"}}));
    let r = find(ob, "JP R");
    assert_eq!(r["flow"], "xtls-rprx-vision");
    assert_eq!(r["tls"]["reality"]["short_id"], "abcd");
    assert_eq!(r["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(find(ob, "HY")["obfs"]["type"], "salamander");
    assert_eq!(find(ob, "H")["username"], "user");
    assert_eq!(find(&out.config["endpoints"], "WG")["peers"][0]["reserved"], json!([1, 2, 3]));
    assert!(out.warnings.iter().any(|w| w.contains("`SN`") && w.contains("version=4 or 6")));
    let s4 = find(ob, "S4");
    assert_eq!((s4["version"].as_u64(), s4["psk"].as_str(), s4["obfs_mode"].as_str()), (Some(4), Some("pw"), Some("http")));
}

#[test]
fn groups() {
    let out = generate_sample();
    let ob = &out.config["outbounds"];
    assert_eq!(find(ob, "Japan")["outbounds"], json!(["JP 1", "JP R"]));
    assert_eq!(find(ob, "Japan")["interval"], "600s");
    assert_eq!(find(ob, "Media")["default"], "Japan");
    assert_eq!(find(ob, "PROXY")["outbounds"].as_array().unwrap().len(), 9);
    assert_eq!(find(ob, "Slow")["idle_timeout"], "3600s", "interval > 30m needs idle_timeout");
    // Ghost состоял только из неподдерживаемого узла → удалён, правило → reject.
    assert!(ob.as_array().unwrap().iter().all(|o| o["tag"] != "Ghost"));
}

#[test]
fn rules_follow_shadowrocket_semantics() {
    let out = generate_sample();
    let rules = out.config["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["action"], "sniff");
    assert_eq!(rules[2], json!({"domain_suffix": ["ads.example.com"], "action": "reject"}));
    assert_eq!(rules[3]["method"], "drop");
    assert_eq!(rules[4]["domain_regex"], json!([r"^a.*c\.example.\.com$"]));
    assert_eq!(rules[5]["type"], "logical");
    assert_eq!(rules[5]["no_drop"], true);
    assert_eq!(rules[6]["invert"], true);
    assert_eq!(rules[6]["action"], "reject", "unavailable group fails closed");

    let pos = |pred: &dyn Fn(&Value) -> bool| rules.iter().position(|r| pred(r)).unwrap();
    let resolve = pos(&|r| r["action"] == "resolve");
    let media_set = pos(&|r| r["rule_set"] == json!(["set-0"]));
    let geo = pos(&|r| r["rule_set"] == json!(["geoip-cn"]));
    let private_lan = pos(&|r| r["ip_cidr"] == json!(["192.168.0.0/16"]));
    let ip = pos(&|r| r["ip_cidr"] == json!(["8.8.8.8/32"]));
    // IP в media.list помечен no-resolve, у 192.168/16 — тоже: резолв только перед 8.8.8.8.
    assert!(media_set < resolve && private_lan < resolve && resolve < ip, "resolve right before first resolving IP rule");
    assert!(geo > ip, "GEOIP moved after explicit rules");
    assert_eq!(out.config["route"]["final"], "PROXY");
    assert!(out.warnings.iter().any(|w| w.contains("USER-AGENT")));
    assert!(out.warnings.iter().any(|w| w.contains("[MITM]")));
}

#[test]
fn rule_sets_and_dns() {
    let out = generate_sample();
    let sets = &out.config["route"]["rule_set"];
    let media = find(sets, "set-0");
    assert_eq!(media["rules"][0]["domain_suffix"], json!(["youtube.com"]));
    assert_eq!(media["rules"][1]["ip_cidr"], json!(["1.0.0.0/24"]));
    let ads = find(sets, "set-1");
    assert_eq!(ads["rules"][0], json!({"domain_suffix": ["doubleclick.net"], "domain": ["ads.example.org"]}));
    assert_eq!(find(sets, "geoip-cn")["format"], "binary");

    let dns = &out.config["dns"];
    let main = find(&dns["servers"], "dns-main");
    assert_eq!(main["detour"], "HK 1");
    assert_eq!(main["domain_resolver"], "dns-local");
    assert_eq!(dns["strategy"], "ipv4_only");
    assert_eq!(out.config["route"]["default_domain_resolver"], "dns-local");
    assert_eq!(find(&dns["servers"], "dns-hosts")["predefined"]["localhost"], json!(["127.0.0.1"]));
}

#[test]
fn policy_names_are_case_insensitive() {
    let conf = "[Proxy]\nA = socks5, 1.1.1.1, 1080\n[Proxy Group]\nYouTube = select, a, proxy\n[Rule]\nDOMAIN,yt.com,YOUTUBE\nFINAL,direct\n";
    let out = generate(&fmt_shadowrocket::parse(conf), &Mem(HashMap::new()), &Options::default()).unwrap();
    assert_eq!(find(&out.config["outbounds"], "YouTube")["outbounds"], json!(["A", "PROXY"]));
    assert_eq!(out.config["route"]["rules"][2]["outbound"], "YouTube");
    assert_eq!(out.config["route"]["final"], "DIRECT");
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
}

#[test]
fn listen_from_config_and_cli() {
    let gen = |conf: &str, opts: Options| generate(&fmt_shadowrocket::parse(conf), &Mem(HashMap::new()), &opts).unwrap().listeners;
    assert_eq!(gen("", Options::default()), ["mixed 127.0.0.1:7890"]);
    assert_eq!(gen("[General]\nhttp-listen = 1087\n", Options::default()), ["mixed 127.0.0.1:1087"]);
    assert_eq!(
        gen("[General]\nhttp-listen = 0.0.0.0:6152\nsocks5-listen = 127.0.0.1:6153\n", Options::default()),
        ["http 0.0.0.0:6152", "socks 127.0.0.1:6153"]
    );
    // CLI главнее конфига.
    let cli = Options { port: Some(9000), listen: Some("0.0.0.0".into()), ..Default::default() };
    assert_eq!(gen("[General]\nhttp-listen = 1087\n", cli), ["mixed 0.0.0.0:9000"]);
}

#[test]
fn rule_origins_match_route_rules() {
    let out = generate_sample();
    let rules = out.config["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), out.rule_origins.len());
    let i = rules.iter().position(|r| r["ip_cidr"] == json!(["8.8.8.8/32"])).unwrap();
    assert!(out.rule_origins[i].contains("IP-CIDR,8.8.8.8/32,PROXY"), "{}", out.rule_origins[i]);
    assert!(out.rule_origins[i - 1].starts_with("(cproxy) resolve"));
}

#[test]
fn redact_hides_secrets() {
    let red = redact(&generate_sample().config).to_string();
    for secret in ["\"pw\"", "11111111-1111-1111-1111-111111111111", "YNXtAzepDqRv9H52osJVDQnznT5AL11eVbvjmyLnU0U="] {
        assert!(!red.contains(secret), "{secret} leaked");
    }
    assert!(red.contains("headless rules omitted"));
}

#[test]
fn missing_final_reject_is_fail_closed() {
    let doc = fmt_shadowrocket::parse("[Rule]\nFINAL,REJECT\n");
    let out = generate(&doc, &Mem(HashMap::new()), &Options::default()).unwrap();
    let rules = out.config["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.last().unwrap()["action"], "reject");
}

/// Прогон через настоящий sing-box, если он доступен (`CPROXY_SING_BOX` или `bin/`).
/// Прогоняет конфиг через настоящий бинарь из `bin/` (нет бинаря — тест пропускается).
fn real_check(name: &str, env: &str, args: &[&str], config: &Value) {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let exe = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    let path = std::env::var(env).unwrap_or_else(|_| format!("{root}/bin/{exe}"));
    if !std::path::Path::new(&path).exists() {
        eprintln!("{name} not found at {path}; skipping");
        return;
    }
    let mut child = std::process::Command::new(&path)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(config.to_string().as_bytes()).unwrap();
    let res = child.wait_with_output().unwrap();
    assert!(
        res.status.success(),
        "{name} check failed: {}{}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
}

#[test]
fn sing_box_accepts_generated_config() {
    // GEOIP нужен реальный .srs — без него проверяем конфиг без этого правила.
    let conf = CONF.replace("GEOIP,CN,DIRECT
", "");
    let out = generate(&fmt_shadowrocket::parse(&conf), &resources(), &Options::default()).unwrap();
    real_check("sing-box", "CPROXY_SING_BOX", &["check", "-c", "stdin"], &out.config);
}

fn node(origin: &str, line: &str) -> Node {
    Node { proxy: fmt_shadowrocket::parse_proxy(1, line).unwrap(), origin: origin.into() }
}

#[test]
fn external_nodes_and_xray() {
    fn port() -> u16 {
        20555
    }
    let nodes = vec![
        node("n#0", "X = vless, a.example, 5035, password=bf000d23-0752-40b4-affe-68f7707a9661, tls=true, obfs=xhttp, path=/ray, obfs-host=a.example, mode=auto, alpn=h2|http/1.1, fp=chrome"),
        node("n#1", "T = trojan, t.example, 443, password=pw"),
        node("n#2", "T = trojan, dup.example, 443, password=pw"),
    ];
    let conf = "[Proxy]
IGNORED = trojan, i.example, 443, password=pw
[Rule]
DOMAIN,x.com,T
FINAL,PROXY
";
    let opts = Options { nodes: Some(nodes), alloc_port: Some(port), ..Default::default() };
    let out = generate(&fmt_shadowrocket::parse(conf), &resources(), &opts).unwrap();
    let tags: Vec<&str> = out.config["outbounds"].as_array().unwrap().iter().filter_map(|o| o["tag"].as_str()).collect();
    assert_eq!(tags, ["DIRECT", "X", "T", "PROXY"], "[Proxy] of rules is replaced by external nodes");
    let x = &out.config["outbounds"][1];
    assert_eq!((x["type"].as_str(), x["server_port"].as_u64()), (Some("socks"), Some(20555)));
    assert!(out.warnings.iter().any(|w| w.contains("n#2") && w.contains("duplicate")));
    let xr = out.xray.as_ref().expect("xray config");
    assert_eq!(xr["inbounds"][0]["port"], 20555);
    assert_eq!(xr["outbounds"][0]["streamSettings"]["network"], "xhttp");
    assert_eq!(xr["outbounds"][0]["streamSettings"]["xhttpSettings"]["xmux"]["maxConcurrency"], "16-32");
    assert_eq!(xr["inbounds"][0]["settings"]["accounts"][0]["pass"], x["password"]);
    // После `resolve` sing-box отдаёт узлу IP; Xray возвращает домен из SNI/Host (ARCHITECTURE.md §8).
    assert_eq!(xr["inbounds"][0]["sniffing"]["routeOnly"], false);
    assert_eq!(redact(xr)["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], "***");
    real_check("sing-box", "CPROXY_SING_BOX", &["check", "-c", "stdin"], &out.config);
    real_check("xray", "CPROXY_XRAY", &["run", "-test", "-format", "json", "-c", "stdin:"], xr);
}

#[test]
fn tun_mode() {
    fn port() -> u16 {
        20777
    }
    let conf = "[General]\ntun-excluded-routes = 10.0.0.0/8, 192.168.0.0/16, 239.255.255.250/32, bogus\n[Rule]\nFINAL,PROXY\n";
    let nodes = vec![node("n#0", "X = vless, a.example, 443, password=bf000d23-0752-40b4-affe-68f7707a9661, tls=true, obfs=xhttp, path=/x")];
    let opts = Options { tun: true, nodes: Some(nodes), alloc_port: Some(port), tun_exclude: vec!["203.0.113.7/32".into()], ..Default::default() };
    let out = generate(&fmt_shadowrocket::parse(conf), &resources(), &opts).unwrap();
    let tun = out.config["inbounds"].as_array().unwrap().iter().find(|i| i["type"] == "tun").expect("tun inbound");
    assert_eq!(tun["auto_route"], true);
    assert_eq!(tun["strict_route"], true);
    assert_eq!(tun["route_exclude_address"], json!(["10.0.0.0/8", "192.168.0.0/16", "239.255.255.250/32", "203.0.113.7/32"]));
    assert!(out.warnings.iter().any(|w| w.contains("bogus")));
    assert_eq!(out.config["route"]["auto_detect_interface"], true);
    // Петля Xray: его процесс идёт DIRECT сразу после служебных правил.
    assert_eq!(out.config["route"]["rules"][2]["process_name"], json!(["xray.exe", "xray"]));
    assert!(out.listeners.iter().any(|l| l == "tun cproxy (fake-ip)"), "{:?}", out.listeners);
    // fake-ip: сервер, правило A/AAAA → fakeip, перед ним — исключения (NCSI Windows, локальные имена).
    let servers = out.config["dns"]["servers"].as_array().unwrap();
    assert!(servers.iter().any(|s| s["type"] == "fakeip" && s["inet4_range"] == "198.18.0.0/15"));
    let rules = out.config["dns"]["rules"].as_array().unwrap();
    let fi = rules.iter().position(|r| r["server"] == "dns-fakeip").expect("fakeip rule");
    assert_eq!(rules[fi]["query_type"], json!(["A", "AAAA"]));
    assert!(rules[fi - 1]["domain_suffix"].as_array().unwrap().iter().any(|d| d == "msftncsi.com"));
    // always-real-ip = * (как в конфиге пользователя) — fake-ip выключен.
    let conf_real = format!("{}
always-real-ip = *
", conf.replace("[Rule]", "always-real-ip = *, *.example
[Rule]"));
    let real = generate(&fmt_shadowrocket::parse(&conf_real.replace("
always-real-ip = *
", "")), &resources(), &opts).unwrap();
    assert!(!real.config["dns"]["servers"].as_array().unwrap().iter().any(|s| s["type"] == "fakeip"));
    assert!(real.listeners.iter().any(|l| l == "tun cproxy"));
    // Пользовательские исключения попадают в правило real-ip.
    let some = generate(&fmt_shadowrocket::parse(&conf.replace("[Rule]", "always-real-ip = *.bank.example, game?.example
[Rule]")), &resources(), &opts).unwrap();
    let r = &some.config["dns"]["rules"].as_array().unwrap()[0];
    assert!(r["domain_suffix"].as_array().unwrap().iter().any(|d| d == "bank.example"));
    assert!(r["domain_regex"].as_array().unwrap().len() >= 1);
    real_check("sing-box", "CPROXY_SING_BOX", &["check", "-c", "stdin"], &some.config);
    // Без TUN — ничего из этого.
    let plain = generate(&fmt_shadowrocket::parse(conf), &resources(), &Options::default()).unwrap();
    assert!(plain.config["route"].get("auto_detect_interface").is_none());
    assert!(!plain.config["inbounds"].as_array().unwrap().iter().any(|i| i["type"] == "tun"));
    real_check("sing-box", "CPROXY_SING_BOX", &["check", "-c", "stdin"], &out.config);
}
