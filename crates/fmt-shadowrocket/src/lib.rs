//! Парсер и писатель `.conf` Shadowrocket.
//!
//! Документ хранит исходные строки как есть, поэтому `parse` → `write`
//! даёт идентичный текст. Типизированные виды (`rules`, `proxies`, `groups`)
//! разбираются по запросу.
//!
//! Источник синтаксиса — оф. мануал https://github.com/LOWERTOP/Shadowrocket (README, «规则类型»,
//! «编写本地节点», «代理分组»). Соответствие sing-box — docs/MAPPING.md.
//! Потребители: `singbox-gen` (генерация), `cli` (check). Инвариант round-trip проверяют
//! тесты `round_trip_is_lossless` и `official_fixtures` (tests/fixtures).

use core_model::{Matcher, ParseError, Proxy, ProxyGroup, Rule};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    /// Номер строки заголовка в файле (с 1).
    pub header_line: usize,
    /// Строки секции без заголовка, включая комментарии и пустые.
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    /// Строки до первой секции.
    pub preamble: Vec<String>,
    pub sections: Vec<Section>,
    crlf: bool,
    trailing_newline: bool,
}

/// Секции, которые сохраняются при экспорте, но исполнения требуют MITM/HTTP-слоя.
pub const MITM_SECTIONS: &[&str] =
    &["URL Rewrite", "Header Rewrite", "Body Rewrite", "Map Local", "Script", "MITM"];

fn section_header(line: &str) -> Option<&str> {
    let t = line.trim();
    t.strip_prefix('[')?.strip_suffix(']')
}

fn is_data(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('#') && !t.starts_with("//") && !t.starts_with(';')
}

pub fn parse(text: &str) -> Document {
    let crlf = text.contains("\r\n");
    let trailing_newline = text.ends_with('\n');
    let mut doc = Document { crlf, trailing_newline, ..Default::default() };
    if text.is_empty() {
        return doc;
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    for (i, line) in body.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(name) = section_header(line) {
            doc.sections.push(Section { name: name.to_string(), header_line: i + 1, lines: Vec::new() });
        } else if let Some(s) = doc.sections.last_mut() {
            s.lines.push(line.to_string());
        } else {
            doc.preamble.push(line.to_string());
        }
    }
    log::debug!(target: "conf", "parsed {} bytes: crlf={crlf}, {} preamble lines", text.len(), doc.preamble.len());
    for s in &doc.sections {
        log::debug!(target: "conf", "section [{}] at line {}: {} lines", s.name, s.header_line, s.lines.len());
    }
    doc
}

pub fn write(doc: &Document) -> String {
    let nl = if doc.crlf { "\r\n" } else { "\n" };
    let mut out: Vec<String> = doc.preamble.clone();
    for s in &doc.sections {
        out.push(format!("[{}]", s.name));
        out.extend(s.lines.iter().cloned());
    }
    let mut text = out.join(nl);
    if doc.trailing_newline {
        text.push_str(nl);
    }
    text
}

impl Document {
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    /// Непустые строки без комментариев с номером строки в файле.
    pub fn data_lines<'a>(&'a self, name: &str) -> impl Iterator<Item = (usize, &'a str)> {
        self.section(name)
            .into_iter()
            .flat_map(|s| s.lines.iter().enumerate().map(move |(i, l)| (s.header_line + i + 1, l)))
            .filter(|(_, l)| is_data(l))
            .map(|(n, l)| (n, l.trim()))
    }

    pub fn rules(&self) -> Result<Vec<Rule>, ParseError> {
        self.data_lines("Rule").map(|(n, l)| parse_rule(n, l)).collect()
    }

    pub fn proxies(&self) -> Result<Vec<Proxy>, ParseError> {
        self.data_lines("Proxy").map(|(n, l)| parse_proxy(n, l)).collect()
    }

    pub fn groups(&self) -> Result<Vec<ProxyGroup>, ParseError> {
        self.data_lines("Proxy Group").map(|(n, l)| parse_group(n, l)).collect()
    }

    /// Пары `key = value` секции (`[General]`, `[Host]`).
    pub fn key_values(&self, section: &str) -> Vec<(usize, String, String)> {
        self.data_lines(section)
            .filter_map(|(n, l)| {
                let (k, v) = l.split_once('=')?;
                Some((n, k.trim().to_string(), v.trim().to_string()))
            })
            .collect()
    }

    /// Последнее значение ключа `[General]` (как в Shadowrocket — последнее побеждает).
    pub fn general(&self, key: &str) -> Option<String> {
        self.key_values("General").into_iter().rev().find(|(_, k, _)| k.eq_ignore_ascii_case(key)).map(|(_, _, v)| v)
    }
}

/// `[General] include = a.conf` (мануал, lazy.conf: «当前配置包含另一个配置 a.conf 的内容，当前配置的优先级高于 a.conf»):
/// документ для генерации, в котором `base` важнее `inc`. Для записи не предназначен (lossless — у исходных
/// документов). Вызывает `cli/src/main.rs::load`. Правила:
/// - `[General]`: строки `inc` перед строками `base` — `general()` берёт последнее значение, поэтому побеждает base;
/// - `[Rule]`: правила base, затем inc; FINAL из inc отбрасывается, если он есть в base;
/// - `[Proxy]`, `[Proxy Group]`, `[Host]`: из inc — только имена/ключи, которых нет в base;
/// - остальные секции — строки inc дописываются; секции, которых нет в base, — целиком.
/// Строки inc помечаются комментарием `# include: <label>`; номера строк после него — уже не номера исходных файлов.
pub fn merge_included(base: &Document, inc: &Document, label: &str) -> Document {
    let mut out = base.clone();
    let marker = format!("# include: {label}");
    let name_of = |l: &str| l.split('=').next().unwrap_or("").trim().to_string();
    for sec in &inc.sections {
        let data: Vec<String> = sec.lines.iter().filter(|l| is_data(l)).cloned().collect();
        let Some(target) = out.sections.iter_mut().find(|s| s.name.eq_ignore_ascii_case(&sec.name)) else {
            let mut lines = vec![marker.clone()];
            lines.extend(sec.lines.iter().cloned());
            out.sections.push(Section { name: sec.name.clone(), header_line: 0, lines });
            continue;
        };
        let lower = sec.name.to_ascii_lowercase();
        let added: Vec<String> = match lower.as_str() {
            "general" => {
                let mut lines = vec![marker.clone()];
                lines.extend(data);
                lines.append(&mut target.lines);
                target.lines = lines;
                continue;
            }
            "rule" => {
                let base_final = target.lines.iter().any(|l| is_data(l) && l.trim().to_ascii_uppercase().starts_with("FINAL"));
                data.into_iter().filter(|l| !(base_final && l.trim().to_ascii_uppercase().starts_with("FINAL"))).collect()
            }
            "proxy" | "proxy group" | "host" => {
                let have: Vec<String> = target.lines.iter().filter(|l| is_data(l)).map(|l| name_of(l)).collect();
                data.into_iter().filter(|l| !have.iter().any(|h| h.eq_ignore_ascii_case(&name_of(l)))).collect()
            }
            _ => data,
        };
        if !added.is_empty() {
            target.lines.push(marker.clone());
            target.lines.extend(added);
        }
    }
    log::debug!(target: "conf", "include {label}: merged {} section(s)", inc.sections.len());
    out
}

fn err(line: usize, message: &str) -> ParseError {
    ParseError { line, message: message.to_string() }
}

/// Делит по запятым верхнего уровня, не заходя внутрь скобок `(...)`.
/// Нужно для логических правил: `AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT` — три части.
pub fn split_top(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur.trim().to_string());
    parts
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',').map(|p| p.trim().to_string()).collect()
}

pub fn parse_rule(line_no: usize, line: &str) -> Result<Rule, ParseError> {
    let parts = split_top(line);
    let kind = parts[0].to_ascii_uppercase();
    // FINAL,POLICY — единственное правило без значения.
    if kind == "FINAL" {
        let policy = parts.get(1).filter(|p| !p.is_empty()).ok_or_else(|| err(line_no, "FINAL without policy"))?;
        return Ok(Rule { kind, value: None, policy: policy.clone(), options: parts[2..].to_vec() });
    }
    if parts.len() < 3 {
        return Err(err(line_no, "rule needs TYPE,value,POLICY"));
    }
    let rule = Rule {
        kind,
        value: Some(parts[1].clone()),
        policy: parts[2].clone(),
        options: parts[3..].to_vec(),
    };
    if matches!(rule.kind.as_str(), "AND" | "OR" | "NOT") {
        parse_matcher(&rule.kind, &parts[1]).map_err(|m| err(line_no, &m))?;
    }
    Ok(rule)
}

/// Строка из файла RULE-SET: `TYPE,value[,option...]` без политики.
/// Используется `singbox-gen/src/rules.rs::Converter::list` (→ inline rule-set, ARCHITECTURE.md §5).
/// Строка без типа, похожая на IP/CIDR, считается `IP-CIDR`.
pub fn parse_list_line(line: &str) -> Option<(String, String, Vec<String>)> {
    let t = line.trim();
    if !is_data(t) {
        return None;
    }
    let parts = split_top(t);
    if parts.len() == 1 {
        let v = &parts[0];
        let looks_ip = v.contains(':') || v.split('/').next()?.parse::<std::net::Ipv4Addr>().is_ok();
        return looks_ip.then(|| ("IP-CIDR".to_string(), v.clone(), Vec::new()));
    }
    Some((parts[0].to_ascii_uppercase(), parts[1].clone(), parts[2..].to_vec()))
}

fn strip_parens(s: &str) -> Option<&str> {
    s.trim().strip_prefix('(')?.strip_suffix(')')
}

/// Разбирает условие правила; для `AND/OR/NOT` значение имеет вид `((A,x),(B,y))`.
pub fn parse_matcher(kind: &str, value: &str) -> Result<Matcher, String> {
    let kind = kind.to_ascii_uppercase();
    if !matches!(kind.as_str(), "AND" | "OR" | "NOT") {
        return Ok(Matcher::Leaf { kind, value: value.to_string() });
    }
    let inner = strip_parens(value).ok_or_else(|| format!("{kind}: expected ((...),(...))"))?;
    let mut children = Vec::new();
    for part in split_top(inner) {
        let sub = strip_parens(&part).ok_or_else(|| format!("{kind}: bad sub-rule `{part}`"))?;
        let (k, v) = sub.split_once(',').ok_or_else(|| format!("{kind}: sub-rule needs TYPE,value"))?;
        children.push(parse_matcher(k.trim(), v.trim())?);
    }
    match kind.as_str() {
        "AND" => Ok(Matcher::And(children)),
        "OR" => Ok(Matcher::Or(children)),
        _ if children.len() == 1 => Ok(Matcher::Not(Box::new(children.remove(0)))),
        _ => Err("NOT takes exactly one sub-rule".into()),
    }
}

fn split_kv(items: &[String]) -> (Vec<String>, Vec<(String, String)>) {
    let mut plain = Vec::new();
    let mut kv = Vec::new();
    for it in items {
        match it.split_once('=') {
            Some((k, v)) if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') => {
                kv.push((k.to_string(), v.trim().to_string()))
            }
            _ => plain.push(it.clone()),
        }
    }
    (plain, kv)
}

pub fn parse_proxy(line_no: usize, line: &str) -> Result<Proxy, ParseError> {
    let (name, rest) = line.split_once('=').ok_or_else(|| err(line_no, "expected `name = ...`"))?;
    let (plain, params) = split_kv(&split_csv(rest));
    if plain.len() < 3 {
        return Err(err(line_no, "proxy needs type, server, port"));
    }
    let port = plain[2].parse().map_err(|_| err(line_no, "invalid port"))?;
    Ok(Proxy {
        name: name.trim().to_string(),
        kind: plain[0].to_ascii_lowercase(),
        server: plain[1].clone(),
        port,
        args: plain[3..].to_vec(),
        params,
    })
}

pub fn parse_group(line_no: usize, line: &str) -> Result<ProxyGroup, ParseError> {
    let (name, rest) = line.split_once('=').ok_or_else(|| err(line_no, "expected `name = ...`"))?;
    let (plain, params) = split_kv(&split_csv(rest));
    let (kind, members) = plain.split_first().ok_or_else(|| err(line_no, "group needs a type"))?;
    Ok(ProxyGroup {
        name: name.trim().to_string(),
        kind: kind.to_ascii_lowercase(),
        members: members.to_vec(),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# my config\n[General]\nbypass-system = true\n\n[Proxy]\nHK = trojan, hk.example.com, 443, password=abc, peer=hk.example.com\nH = http, 1.2.3.4, 8080, user, pass\n\n[Proxy Group]\nPROXY = select, HK, DIRECT\nAuto = url-test, HK, url=http://www.gstatic.com/generate_204, interval=600\n\n[Rule]\n// ads\nDOMAIN-SUFFIX,ads.example.com,REJECT\nRULE-SET,https://example.com/a.list,PROXY\nGEOIP,CN,DIRECT,no-resolve\nAND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP\nFINAL,PROXY\n\n[MITM]\nhostname = *.example.com\n";

    #[test]
    fn include_base_wins() {
        let base = parse("[General]\ndns-server = 1.1.1.1\ninclude = a.conf\n[Proxy]\nA = trojan, a.example, 443, password=x\n[Rule]\nDOMAIN,a.com,DIRECT\nFINAL,PROXY\n");
        let inc = parse("[General]\ndns-server = 8.8.8.8\nipv6 = false\n[Proxy]\nA = trojan, other.example, 443, password=y\nB = trojan, b.example, 443, password=z\n[Proxy Group]\nG = select, B\n[Rule]\nDOMAIN,b.com,G\nFINAL,DIRECT\n[MITM]\nhostname = *.x\n");
        let m = merge_included(&base, &inc, "a.conf");
        assert_eq!(m.general("dns-server").as_deref(), Some("1.1.1.1"), "base wins in [General]");
        assert_eq!(m.general("ipv6").as_deref(), Some("false"), "new keys come from include");
        let names: Vec<String> = m.proxies().unwrap().into_iter().map(|p| (p.name + "@" + &p.server)).collect();
        assert_eq!(names, ["A@a.example", "B@b.example"], "base node kept, only new names added");
        let rules: Vec<String> = m.data_lines("Rule").map(|(_, l)| l.to_string()).collect();
        assert_eq!(rules, ["DOMAIN,a.com,DIRECT", "FINAL,PROXY", "DOMAIN,b.com,G"], "include FINAL dropped, base rules first");
        assert_eq!(m.groups().unwrap()[0].name, "G");
        assert!(m.section("MITM").is_some());
        assert_eq!(write(&base), "[General]\ndns-server = 1.1.1.1\ninclude = a.conf\n[Proxy]\nA = trojan, a.example, 443, password=x\n[Rule]\nDOMAIN,a.com,DIRECT\nFINAL,PROXY\n", "base untouched");
    }

    #[test]
    fn round_trip_is_lossless() {
        assert_eq!(write(&parse(SAMPLE)), SAMPLE);
        let crlf = SAMPLE.replace('\n', "\r\n");
        assert_eq!(write(&parse(&crlf)), crlf);
        let no_nl = SAMPLE.trim_end_matches('\n');
        assert_eq!(write(&parse(no_nl)), no_nl);
    }

    #[test]
    fn typed_views() {
        let doc = parse(SAMPLE);
        let rules = doc.rules().unwrap();
        assert_eq!(rules.len(), 5);
        assert_eq!(rules[2].options, vec!["no-resolve"]);
        assert_eq!(rules[3].policy, "REJECT-NO-DROP");
        assert_eq!(rules[4].kind, "FINAL");
        assert_eq!(rules[4].value, None);

        let p = doc.proxies().unwrap();
        assert_eq!((p[0].kind.as_str(), p[0].port), ("trojan", 443));
        assert_eq!(p[0].param(&["PASSWORD"]), Some("abc"));
        assert_eq!(p[1].args, vec!["user", "pass"]);

        let g = doc.groups().unwrap();
        assert_eq!(g[0].members, vec!["HK", "DIRECT"]);
        assert_eq!(g[1].param("interval"), Some("600"));
        assert_eq!(doc.general("bypass-system").as_deref(), Some("true"));
    }

    #[test]
    fn logical_rules() {
        let m = parse_matcher("OR", "((AND,((DOMAIN,a.com),(DST-PORT,443))),(NOT,((PROTOCOL,UDP))))").unwrap();
        let leaf = |k: &str, v: &str| Matcher::Leaf { kind: k.into(), value: v.into() };
        assert_eq!(
            m,
            Matcher::Or(vec![
                Matcher::And(vec![leaf("DOMAIN", "a.com"), leaf("DST-PORT", "443")]),
                Matcher::Not(Box::new(leaf("PROTOCOL", "UDP"))),
            ])
        );
        assert!(parse_rule(1, "AND,(DOMAIN,x),DIRECT").is_err());
    }

    #[test]
    fn bad_rule_reports_file_line() {
        let doc = parse("[General]\n\n[Rule]\nDOMAIN,only-two\n");
        assert_eq!(doc.rules().unwrap_err().line, 4);
    }

    #[test]
    fn list_lines() {
        assert_eq!(parse_list_line("10.0.0.0/8").unwrap().0, "IP-CIDR");
        assert_eq!(parse_list_line("2001:db8::/32").unwrap().0, "IP-CIDR");
        assert!(parse_list_line("# comment").is_none());
        assert_eq!(parse_list_line("IP-CIDR,1.1.1.1/32,no-resolve").unwrap().2, vec!["no-resolve"]);
    }

    /// Официальные примеры из LOWERTOP/Shadowrocket (см. tests/fixtures/README.md).
    #[test]
    fn official_fixtures() {
        // Встроены при сборке: тест не зависит от пути (кросс-сборка под Linux запускается в WSL).
        let fixtures = [("lazy.conf", include_str!("../tests/fixtures/lazy.conf")), ("lazy_group.conf", include_str!("../tests/fixtures/lazy_group.conf"))];
        for (name, text) in fixtures {
            let doc = parse(text);
            assert_eq!(write(&doc), text, "{name}: round-trip");
            let rules = doc.rules().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(rules.iter().any(|r| r.kind == "FINAL"), "{name}: FINAL");
            doc.groups().unwrap_or_else(|e| panic!("{name}: {e}"));
            doc.proxies().unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}
