/// Generate a validated newtype with wildcard support, serde, and Display.
macro_rules! validated_newtype {
    (
        $(#[$meta:meta])*
        $vis:vis struct $Name:ident;
        max_len = $max:expr,
        error_prefix = $prefix:expr,
        error_pattern = $pattern:expr
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        $vis struct $Name(String);

        impl $Name {
            pub fn new(s: impl Into<String>) -> Result<Self, &'static str> {
                let s = s.into();
                if s == "*" {
                    return Ok(Self(s));
                }
                if s.is_empty() || s.len() > $max {
                    return Err(concat!($prefix, " must be 1-63 characters"));
                }
                let bytes = s.as_bytes();
                if !bytes[0].is_ascii_lowercase() {
                    return Err(concat!($prefix, " must start with a lowercase letter"));
                }
                if !bytes.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-'
                }) {
                    return Err(concat!($prefix, " must match ", $pattern));
                }
                Ok(Self(s))
            }

            pub fn wildcard() -> Self {
                Self("*".to_owned())
            }

            pub fn is_wildcard(&self) -> bool {
                self.0 == "*"
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $Name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$Name> for String {
            fn from(v: $Name) -> String {
                v.0
            }
        }
    };
}

mod database;
mod environment;
mod operation;
mod result_summary;
mod selector;

pub use database::DatabaseName;
pub use environment::Environment;
pub use operation::Operation;
pub use result_summary::ResultSummary;
pub use selector::{Selector, SelectorParseError};
