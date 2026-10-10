use super::*;
use serde_json::Value;

const SINGBOX: &str = r#"{
  "outbounds": [
    {
      "type": "vless", "tag": "x § 0", "server": "a.example", "server_port": 5035,
      "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
      "tls": {"enabled": true, "server_name": "a.example", "alpn": ["h2", "http/1.1"],
              "utls": {"enabled": true, "fingerprint": "chrome"}},
      "transport": {"type": "xhttp", "mode": "auto", "host": "a.example", "path": "/ray"},
      "packet_encoding": "xudp"
    },
    {"type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "server_port": 8388, "method": "aes-128-gcm", "password": "pw",
     "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=bing.com", "multiplex": {}},
    {"type": "selector", "tag": "sel", "outbounds": ["ss"]},
    {"type": "direct", "tag": "direct"}
  ],
  "endpoints": [
    {"type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"], "private_key": "YNXtAzepDqRv9H52osJVDQnznT5AL11eVbvjmyLnU0U=",
     "peers": [{"address": "2.2.2.2", "port": 51820, "public_key": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=", "reserved": [1, 2, 3]}]}
  ]
}"#;

#[test]
fn singbox_json() {
    let p = parse(SINGBOX, "nodes.json").unwrap();
    assert_eq!(p.format, "sing-box JSON");
    let names: Vec<&str> = p.nodes.iter().map(|n| n.proxy.name.as_str()).collect();
    assert_eq!(names, ["x § 0", "ss", "wg"]);
    let v = &p.nodes[0].proxy;
    assert_eq!((v.kind.as_str(), v.server.as_str(), v.port), ("vless", "a.example", 5035));
    for (k, want) in [("password", "bf000d23-0752-40b4-affe-68f7707a9661"), ("obfs", "xhttp"), ("path", "/ray"),
        ("obfs-host", "a.example"), ("mode", "auto"), ("sni", "a.example"), ("alpn", "h2|http/1.1"), ("fp", "chrome"), ("tls", "true")]
    {
        assert_eq!(v.param(&[k]), Some(want), "{k}");
    }
    assert_eq!(p.nodes[1].proxy.param(&["obfs"]), Some("http"));
    assert_eq!(p.nodes[2].proxy.param(&["reserved"]), Some("1/2/3"));
    // multiplex не разобран → warning; selector → warning.
    assert!(p.warnings.iter().any(|w| w.contains("multiplex")), "{:?}", p.warnings);
    assert!(p.warnings.iter().any(|w| w.contains("groups from sing-box JSON")));
}

#[test]
fn shadowrocket_proxy_section() {
    let p = parse("[Proxy]\r\nA = trojan, a.example, 443, password=pw\r\n", "n.conf").unwrap();
    assert_eq!(p.nodes.len(), 1);
    assert_eq!(p.nodes[0].origin, "n.conf [Proxy] line 2");
}

#[test]
fn detection() {
    assert!(parse("hello", "x").is_err());
    assert!(parse("{\"a\":1}", "x").is_err());
    assert!(looks_like_rules("[Rule]\nFINAL,DIRECT\n"));
    assert!(!looks_like_rules(SINGBOX));
}

fn b64enc(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
const PBK: &str = "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON-GwPq7SOV4";

fn links() -> String {
    let vmess = b64enc(
        format!(r#"{{"v":"2","ps":"VM ws","add":"vm.example","port":"443","id":"{UUID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example","path":"/vm","tls":"tls","sni":"vm.example"}}"#)
            .as_bytes(),
    );
    let ss_user = b64enc(b"aes-256-gcm:pw");
    [
        format!("vless://{UUID}@r.example:443?security=reality&sni=www.apple.com&fp=chrome&pbk={PBK}&sid=abcd&flow=xtls-rprx-vision&type=tcp#VL%20Reality"),
        format!("vless://{UUID}@x.example:5035?security=tls&sni=x.example&alpn=h2,http/1.1&fp=chrome&type=xhttp&path=%2Fray&host=x.example&mode=auto#VL%20XHTTP"),
        format!("vless://{UUID}@g.example:443?security=tls&type=grpc&serviceName=svc#VL%20gRPC"),
        format!("vmess://{vmess}"),
        "trojan://p%40ss@t.example:443?sni=t.example&type=ws&path=/tr&host=t.example#TR".to_string(),
        format!("ss://{ss_user}@s.example:8388#SS"),
        "ss://2022-blake3-aes-128-gcm:a2V5a2V5a2V5a2V5a2V5aw%3D%3D@s2.example:8388#SS2022".to_string(),
        "ss://YWVzLTEyOC1nY206cHdAbGVnYWN5LmV4YW1wbGU6ODM4OA==#SSlegacy".to_string(),
        "hy2://auth@h.example:443,20000-30000?sni=h.example&obfs=salamander&obfs-password=ob&insecure=1#HY2".to_string(),
        format!("tuic://{UUID}:pw@tu.example:443?congestion_control=bbr&sni=tu.example&alpn=h3#TUIC"),
        format!("socks://{}@so.example:1080#SOCKS", b64enc(b"user:pass")),
        "anytls://pw@a.example:443?sni=a.example#ANY".to_string(),
        "wireguard://YNXtAzepDqRv9H52osJVDQnznT5AL11eVbvjmyLnU0U%3D@w.example:51820?publickey=Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON%2BGwPq7SOV4%3D&address=10.0.0.2/32&reserved=1,2,3#WG".to_string(),
        "ssr://abc".to_string(),
    ]
    .join("\n")
}

const CLASH: &str = r#"
port: 7890
proxies:
  - {name: C-SS, type: ss, server: s.example, port: 8388, cipher: aes-128-gcm, password: pw, plugin: obfs, plugin-opts: {mode: tls, host: bing.com}}
  - name: C-VL
    type: vless
    server: v.example
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    tls: true
    servername: www.apple.com
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON-GwPq7SOV4
      short-id: abcd
  - name: C-VM
    type: vmess
    server: vm.example
    port: 443
    uuid: bf000d23-0752-40b4-affe-68f7707a9661
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts: {path: /vm, headers: {Host: cdn.example}}
  - {name: C-HY2, type: hysteria2, server: h.example, port: 443, password: pw, obfs: salamander, obfs-password: ob, sni: h.example}
  - {name: C-TU, type: tuic, server: t.example, port: 443, uuid: bf000d23-0752-40b4-affe-68f7707a9661, password: pw, alpn: [h3]}
  - {name: C-TR, type: trojan, server: tr.example, port: 443, password: pw, network: grpc, grpc-opts: {grpc-service-name: g}}
  - {name: C-WG, type: wireguard, server: w.example, port: 51820, private-key: YNXtAzepDqRv9H52osJVDQnznT5AL11eVbvjmyLnU0U=, public-key: Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=, ip: 10.0.0.2, reserved: [1, 2, 3]}
  - {name: C-SSR, type: ssr, server: r.example, port: 1}
  - {name: C-VM, type: vmess, server: dup.example, port: 443, uuid: bf000d23-0752-40b4-affe-68f7707a9661}
proxy-groups:
  - {name: G, type: select, proxies: [C-SS]}
"#;

const XRAY: &str = r#"{
  "remarks": "X remarks",
  "outbounds": [
    {"tag": "proxy", "protocol": "vless",
     "settings": {"vnext": [{"address": "x.example", "port": 443, "users": [{"id": "bf000d23-0752-40b4-affe-68f7707a9661", "encryption": "none"}]}]},
     "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "x.example", "fingerprint": "chrome", "alpn": ["h2"]},
                        "xhttpSettings": {"path": "/x", "host": "x.example", "mode": "stream-one"}}},
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}
  ]
}"#;

const XRAY_FLAT: &str = r#"[
  {"remarks": "A", "outbounds": [{"protocol": "vless", "settings": {"address": "a.example", "port": 443, "id": "bf000d23-0752-40b4-affe-68f7707a9661", "flow": "xtls-rprx-vision", "encryption": "none"},
     "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {"serverName": "www.apple.com", "publicKey": "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON-GwPq7SOV4", "shortId": "ab", "fingerprint": "chrome"}}}]},
  {"remarks": "B", "outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "b.example", "port": 443, "password": "pw"}]},
     "streamSettings": {"network": "ws", "wsSettings": {"path": "/b", "host": "b.example"}}}]}
]"#;

fn names(p: &Parsed) -> Vec<&str> {
    p.nodes.iter().map(|n| n.proxy.name.as_str()).collect()
}

fn param<'a>(p: &'a Parsed, name: &str, key: &str) -> Option<&'a str> {
    p.nodes.iter().find(|n| n.proxy.name == name).and_then(|n| n.proxy.param(&[key]))
}

#[test]
fn link_list() {
    let p = parse(&links(), "sub").unwrap();
    assert_eq!(p.format, "links");
    assert_eq!(names(&p), ["VL Reality", "VL XHTTP", "VL gRPC", "VM ws", "TR", "SS", "SS2022", "SSlegacy", "HY2", "TUIC", "SOCKS", "ANY", "WG"]);
    assert_eq!(param(&p, "VL Reality", "pbk"), Some(PBK));
    assert_eq!(param(&p, "VL Reality", "flow"), Some("xtls-rprx-vision"));
    assert_eq!(param(&p, "VL XHTTP", "obfs"), Some("xhttp"));
    assert_eq!(param(&p, "VL XHTTP", "path"), Some("/ray"));
    assert_eq!(param(&p, "VL XHTTP", "alpn"), Some("h2|http/1.1"));
    assert_eq!(param(&p, "VL gRPC", "grpc-service-name"), Some("svc"));
    assert_eq!(param(&p, "VM ws", "obfs-host"), Some("cdn.example"));
    assert_eq!(param(&p, "TR", "password"), Some("p@ss"));
    assert_eq!(param(&p, "SS", "method"), Some("aes-256-gcm"));
    assert_eq!(param(&p, "SS2022", "password"), Some("a2V5a2V5a2V5a2V5a2V5aw=="));
    let legacy = p.nodes.iter().find(|n| n.proxy.name == "SSlegacy").unwrap();
    assert_eq!((legacy.proxy.server.as_str(), legacy.proxy.port), ("legacy.example", 8388));
    let hy = p.nodes.iter().find(|n| n.proxy.name == "HY2").unwrap();
    assert_eq!(hy.proxy.port, 443);
    assert_eq!(param(&p, "HY2", "obfs-password"), Some("ob"));
    assert_eq!(param(&p, "SOCKS", "username"), Some("user"));
    assert_eq!(param(&p, "WG", "reserved"), Some("1/2/3"));
    assert!(p.warnings.iter().any(|w| w.contains("ssr://") && w.contains("ShadowsocksR")), "{:?}", p.warnings);
    // Секреты не попадают в warnings.
    assert!(!p.warnings.iter().any(|w| w.contains("abc")));
}

#[test]
fn base64_subscription() {
    let p = parse(&b64enc(links().as_bytes()), "sub").unwrap();
    assert_eq!(p.format, "base64 links");
    assert_eq!(p.nodes.len(), 13);
}

#[test]
fn clash_yaml() {
    let p = parse(CLASH, "clash.yaml").unwrap();
    assert_eq!(p.format, "Clash YAML");
    assert_eq!(names(&p), ["C-SS", "C-VL", "C-VM", "C-HY2", "C-TU", "C-TR", "C-WG", "C-VM 2"]);
    assert_eq!(param(&p, "C-SS", "obfs"), Some("tls"));
    assert_eq!(param(&p, "C-VL", "sid"), Some("abcd"));
    assert_eq!(param(&p, "C-VM", "path"), Some("/vm"));
    assert_eq!(param(&p, "C-TR", "grpc-service-name"), Some("g"));
    assert_eq!(param(&p, "C-WG", "reserved"), Some("1/2/3"));
    assert!(p.warnings.iter().any(|w| w.contains("C-SSR")));
}

#[test]
fn xray_json() {
    let p = parse(XRAY, "x.json").unwrap();
    assert_eq!(p.format, "Xray JSON");
    assert_eq!(names(&p), ["X remarks"]);
    assert_eq!(param(&p, "X remarks", "mode"), Some("stream-one"));
    let p = parse(XRAY_FLAT, "x.json").unwrap();
    assert_eq!(names(&p), ["A", "B"]);
    assert_eq!(param(&p, "A", "pbk"), Some(PBK));
    assert_eq!(param(&p, "B", "obfs"), Some("websocket"));
    assert_eq!(param(&p, "B", "tls"), Some("true"));
}

struct NoRes;
impl singbox_gen::Resources for NoRes {
    fn text(&self, _: &str) -> Option<String> {
        None
    }
    fn path(&self, _: &str) -> Option<String> {
        None
    }
}

/// Прогоняет конфиг через настоящий бинарь из `bin/` (нет бинаря — пропуск).
fn real_check(name: &str, args: &[&str], config: &Value) {
    let exe = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    let path = format!("{}/../../bin/{exe}", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&path).exists() {
        eprintln!("{name} not found; skipping");
        return;
    }
    use std::io::Write;
    let mut child = std::process::Command::new(&path)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(config.to_string().as_bytes()).unwrap();
    let r = child.wait_with_output().unwrap();
    assert!(r.status.success(), "{name}: {}{}", String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&r.stderr));
}

/// Все узлы всех форматов → генератор → настоящие `sing-box check` и `xray -test`.
#[test]
fn all_formats_accepted_by_cores() {
    let mut nodes = Vec::new();
    for (text, label) in [(links(), "links"), (CLASH.to_string(), "clash"), (XRAY.to_string(), "xray"), (XRAY_FLAT.to_string(), "xray2"), (SINGBOX.to_string(), "sb")] {
        let mut p = parse(&text, label).unwrap();
        for n in &mut p.nodes {
            n.proxy.name = format!("{label}: {}", n.proxy.name);
        }
        nodes.extend(p.nodes);
    }
    let total = nodes.len();
    fn port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }
    let opts = singbox_gen::Options { nodes: Some(nodes), alloc_port: Some(port), ..Default::default() };
    let out = singbox_gen::generate(&fmt_shadowrocket::parse("[Rule]\nFINAL,PROXY\n"), &NoRes, &opts).unwrap();
    let skipped: Vec<&String> = out.warnings.iter().filter(|w| w.contains("skipped")).collect();
    assert!(skipped.is_empty(), "nodes rejected by generator: {skipped:#?}");
    let proxy = out.config["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "PROXY").unwrap();
    assert_eq!(proxy["outbounds"].as_array().unwrap().len(), total);
    real_check("sing-box", &["check", "-c", "stdin"], &out.config);
    let xr = out.xray.as_ref().expect("xhttp nodes → xray");
    assert_eq!(xr["outbounds"].as_array().unwrap().len(), 3, "links/xray/sing-box xhttp");
    real_check("xray", &["run", "-test", "-format", "json", "-c", "stdin:"], xr);
}
