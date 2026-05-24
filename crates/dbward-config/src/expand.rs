use std::sync::LazyLock;

use regex::Regex;

use crate::ConfigError;

/// Regex for `${VAR}` and `${VAR:-default}`.
pub const ENV_VAR_PATTERN: &str = r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}";

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(ENV_VAR_PATTERN).expect("BUG: invalid ENV_VAR_PATTERN regex"));

/// Expand environment variables in a string.
/// - `${VAR}` — error if undefined
/// - `${VAR:-default}` — use default if undefined
pub fn expand_env_vars(input: &str) -> Result<String, ConfigError> {
    expand_env_vars_with_context(input, "")
}

pub(crate) fn expand_env_vars_with_context(
    input: &str,
    context: &str,
) -> Result<String, ConfigError> {
    if !input.contains("${") {
        return Ok(input.to_string());
    }

    let mut err: Option<ConfigError> = None;
    let result = ENV_RE.replace_all(input, |caps: &regex::Captures| {
        if err.is_some() {
            return String::new();
        }
        let var = &caps[1];
        let default = caps.get(2).map(|m| m.as_str());

        if let Some(d) = default
            && d.contains("${")
        {
            err = Some(ConfigError::NestedExpansion {
                context: context.to_string(),
            });
            return String::new();
        }

        match std::env::var(var) {
            Ok(v) => v,
            Err(_) => {
                if let Some(d) = default {
                    d.to_string()
                } else {
                    err = Some(ConfigError::UndefinedEnvVar {
                        var: var.to_string(),
                        context: context.to_string(),
                    });
                    String::new()
                }
            }
        }
    });

    if let Some(e) = err {
        return Err(e);
    }

    let expanded = result.into_owned();
    if expanded.contains("${") {
        return Err(ConfigError::MalformedExpansion {
            context: context.to_string(),
        });
    }

    Ok(expanded)
}

/// Recursively expand environment variables in a TOML value tree.
pub fn expand_toml_value(value: &mut toml::Value, path: &str) -> Result<(), ConfigError> {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table.iter_mut() {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                expand_toml_value(val, &child_path)?;
            }
        }
        toml::Value::Array(arr) => {
            for (i, val) in arr.iter_mut().enumerate() {
                expand_toml_value(val, &format!("{path}[{i}]"))?;
            }
        }
        toml::Value::String(s) if s.contains("${") => {
            *s = expand_env_vars_with_context(s, path)?;
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

    #[test]
    fn simple_expansion() {
        with_env(&[("CFGTEST_HOST", Some("localhost"))], || {
            let result = expand_env_vars("http://${CFGTEST_HOST}:8080").unwrap();
            assert_eq!(result, "http://localhost:8080");
        });
    }

    #[test]
    fn default_value_used_when_undefined() {
        with_env(&[("CFGTEST_MISSING", None)], || {
            let result = expand_env_vars("${CFGTEST_MISSING:-fallback}").unwrap();
            assert_eq!(result, "fallback");
        });
    }

    #[test]
    fn defined_var_ignores_default() {
        with_env(&[("CFGTEST_SET", Some("real"))], || {
            let result = expand_env_vars("${CFGTEST_SET:-fallback}").unwrap();
            assert_eq!(result, "real");
        });
    }

    #[test]
    fn undefined_without_default_is_error() {
        with_env(&[("CFGTEST_UNDEF", None)], || {
            let err = expand_env_vars("${CFGTEST_UNDEF}").unwrap_err();
            assert!(err.to_string().contains("CFGTEST_UNDEF"));
        });
    }

    #[test]
    fn nested_expansion_rejected() {
        with_env(&[("CFGTEST_OUTER", None)], || {
            let err = expand_env_vars("${CFGTEST_OUTER:-${INNER}}").unwrap_err();
            assert!(err.to_string().contains("nested"));
        });
    }

    #[test]
    fn no_expansion_needed() {
        let result = expand_env_vars("plain text").unwrap();
        assert_eq!(result, "plain text");
    }

    #[test]
    fn toml_value_expansion() {
        with_env(&[("CFGTEST_PORT", Some("9090"))], || {
            let mut val: toml::Value = toml::from_str(r#"port = "${CFGTEST_PORT}""#).unwrap();
            expand_toml_value(&mut val, "").unwrap();
            assert_eq!(val["port"].as_str().unwrap(), "9090");
        });
    }
}
