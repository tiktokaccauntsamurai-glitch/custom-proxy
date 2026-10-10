//! Внутренняя модель конфигурации, не привязанная к конкретному формату.
//!
//! Только типы, без логики разбора/генерации (docs/ARCHITECTURE.md §7).
//! - Заполняет: `fmt-shadowrocket`, `fmt-nodes` (источники узлов; позже `fmt-surge-qx-loon`).
//! - Читает: `singbox-gen` (→ JSON sing-box), `cli`.
//! - Имена параметров в `Proxy::params` — в исходном виде формата (ключи Shadowrocket),
//!   синонимы разрешает потребитель (`singbox-gen/src/outbound.rs`).

/// Правило маршрутизации: `TYPE,value,POLICY[,option...]` или `FINAL,POLICY`.
/// Для логических правил (`AND`/`OR`/`NOT`) `value` хранит исходный
/// `((...),(...))`, разбор — через [`Matcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: String,
    pub value: Option<String>,
    pub policy: String,
    pub options: Vec<String>,
}

impl Rule {
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o.eq_ignore_ascii_case(name))
    }
}

/// Условие правила без политики: лист или логическая комбинация.
/// Строит `fmt_shadowrocket::parse_matcher`; в sing-box превращается в headless-правило
/// (`singbox-gen/src/rules.rs::Converter::convert`; And/Or → `type: logical`, Not → `invert`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matcher {
    Leaf { kind: String, value: String },
    And(Vec<Matcher>),
    Or(Vec<Matcher>),
    Not(Box<Matcher>),
}

/// Сервер из секции `[Proxy]`: `name = type, server, port, arg..., key=value...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxy {
    pub name: String,
    pub kind: String,
    pub server: String,
    pub port: u16,
    /// Позиционные аргументы после порта (например user/pass для http/socks5).
    pub args: Vec<String>,
    pub params: Vec<(String, String)>,
}

impl Proxy {
    /// Первый параметр из списка синонимов (ключи без учёта регистра).
    pub fn param(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| {
            self.params.iter().find(|(pk, _)| pk.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str())
        })
    }

    pub fn flag(&self, keys: &[&str]) -> bool {
        self.param(keys).is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    }
}

/// Узел вместе с происхождением (для warnings и лога): `[Proxy] line 3` или
/// `nodes #2 (sing-box JSON)`. Собирает `fmt-nodes` / `cli`, потребляет `singbox-gen::Options::nodes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub proxy: Proxy,
    pub origin: String,
}

/// Группа из секции `[Proxy Group]`: `name = type, member, ..., key=value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: String,
    pub members: Vec<String>,
    pub params: Vec<(String, String)>,
}

impl ProxyGroup {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }
}

/// Результат разбора строки, который нельзя интерпретировать.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}
