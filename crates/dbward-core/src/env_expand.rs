use regex::Regex;
use std::sync::LazyLock;

use crate::Error;

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").unwrap());

/// Expand `${VAR}` and `${VAR:-default}` in all string values of a TOML tree.
pub fn expand_env_vars(value: &mut toml::Value) -> Result<(), Error> {
    walk(value, "")
}

fn walk(value: &mut toml::Value, path: &str) -> Result<(), Error> {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table.iter_mut() {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                walk(val, &child_path)?;
            }
        }
        toml::Value::Array(arr) => {
            for (i, val) in arr.iter_mut().enumerate() {
                walk(val, &format!("{path}[{i}]"))?;
            }
        }
        toml::Value::String(s) => {
            if s.contains("${") {
                let mut err: Option<Error> = None;
                let expanded = ENV_RE.replace_all(s, |caps: &regex::Captures| {
                    if err.is_some() {
                        return String::new();
                    }
                    let var = &caps[1];
                    let default = caps.get(2).map(|m| m.as_str());

                    if let Some(d) = default {
                        if d.contains("${") {
                            err = Some(Error::Config(format!(
                                "{path}: nested ${{}} expansion is not supported"
                            )));
                            return String::new();
                        }
                    }

                    match std::env::var(var) {
                        Ok(v) => v,
                        Err(_) => {
                            if let Some(d) = default {
                                d.to_string()
                            } else {
                                err = Some(Error::Config(format!(
                                    "{path}: environment variable {var} is not set"
                                )));
                                String::new()
                            }
                        }
                    }
                });

                if let Some(e) = err {
                    return Err(e);
                }

                // Check for leftover unexpanded ${
                if expanded.contains("${") {
                    return Err(Error::Config(format!("{path}: malformed ${{}} expression")));
                }

                *s = expanded.into_owned();
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        let originals: Vec<_> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, original) in &originals {
            match original {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }

    fn expand(toml_str: &str) -> Result<toml::Value, Error> {
        let mut val: toml::Value = toml::from_str(toml_str).unwrap();
        expand_env_vars(&mut val)?;
        Ok(val)
    }

    #[test]
    fn simple_expansion() {
        with_env(&[("TEST_HOST", Some("localhost"))], || {
            let val = expand(r#"host = "${TEST_HOST}""#).unwrap();
            assert_eq!(val["host"].as_str().unwrap(), "localhost");
        });
    }

    #[test]
    fn embedded_in_url() {
        with_env(
            &[("DB_USER", Some("admin")), ("DB_PASS", Some("s3cret"))],
            || {
                let val = expand(r#"url = "postgres://${DB_USER}:${DB_PASS}@host/db""#).unwrap();
                assert_eq!(
                    val["url"].as_str().unwrap(),
                    "postgres://admin:s3cret@host/db"
                );
            },
        );
    }

    #[test]
    fn default_value() {
        with_env(&[("UNSET_VAR_TEST", None)], || {
            let mut val: toml::Value =
                toml::from_str(r#"v = "${UNSET_VAR_TEST:-fallback}""#).unwrap();
            expand_env_vars(&mut val).unwrap();
            assert_eq!(val["v"].as_str().unwrap(), "fallback");
        });
    }

    #[test]
    fn missing_var_error() {
        with_env(&[("MISSING_VAR_XYZ", None)], || {
            let mut val: toml::Value = toml::from_str(r#"token = "${MISSING_VAR_XYZ}""#).unwrap();
            let err = expand_env_vars(&mut val).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("MISSING_VAR_XYZ"), "got: {msg}");
            assert!(msg.contains("not set"), "got: {msg}");
            assert!(msg.contains("token"), "got: {msg}");
        });
    }

    #[test]
    fn nested_table() {
        with_env(&[("SRV_TOKEN", Some("dbw_abc"))], || {
            let val = expand(
                r#"
                [server]
                token = "${SRV_TOKEN}"
                "#,
            )
            .unwrap();
            assert_eq!(val["server"]["token"].as_str().unwrap(), "dbw_abc");
        });
    }

    #[test]
    fn array_expansion() {
        with_env(&[("HOOK_URL", Some("https://hooks.example.com"))], || {
            let val = expand(
                r#"
                [[webhooks]]
                url = "${HOOK_URL}"
                "#,
            )
            .unwrap();
            assert_eq!(
                val["webhooks"][0]["url"].as_str().unwrap(),
                "https://hooks.example.com"
            );
        });
    }

    #[test]
    fn empty_env_value() {
        with_env(&[("EMPTY_VAR", Some(""))], || {
            let val = expand(r#"v = "${EMPTY_VAR}""#).unwrap();
            assert_eq!(val["v"].as_str().unwrap(), "");
        });
    }

    #[test]
    fn empty_default_value() {
        with_env(&[("EMPTY_DEFAULT_TEST", None)], || {
            let val = expand(r#"v = "${EMPTY_DEFAULT_TEST:-}""#).unwrap();
            assert_eq!(val["v"].as_str().unwrap(), "");
        });
    }

    #[test]
    fn malformed_empty_var_name_errors() {
        let err = expand(r#"v = "${}""#).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }

    #[test]
    fn malformed_special_char_var_name_errors() {
        let err = expand(r#"v = "${DB-PASS}""#).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }

    #[test]
    fn no_expansion_needed() {
        let val = expand(r#"v = "plain string""#).unwrap();
        assert_eq!(val["v"].as_str().unwrap(), "plain string");
    }

    #[test]
    fn non_string_values_untouched() {
        let val = expand(
            r#"
            port = 5432
            enabled = true
            "#,
        )
        .unwrap();
        assert_eq!(val["port"].as_integer().unwrap(), 5432);
        assert!(val["enabled"].as_bool().unwrap());
    }
}
