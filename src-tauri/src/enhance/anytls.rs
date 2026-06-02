use serde_yaml_ng::{Mapping, Value};

/// Mihomo enforces YAML `fingerprint` on AnyTLS outbounds, while v2rayN's
/// sing-box path for AnyTLS does not honor URI `pcs`. Wrong panel pins therefore
/// break Clash but not v2rayN. Strip leaf pin and skip cert verify instead.
pub fn relax_anytls_tls_verify(mut config: Mapping) -> Mapping {
    let Some(Value::Sequence(proxies)) = config.get_mut("proxies") else {
        return config;
    };

    for proxy in proxies.iter_mut() {
        let Some(map) = proxy.as_mapping_mut() else {
            continue;
        };

        let is_anytls = map
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("anytls"));

        if !is_anytls {
            continue;
        }

        map.remove("fingerprint");
        map.insert(
            Value::String("skip-cert-verify".into()),
            Value::Bool(true),
        );
    }

    config
}
