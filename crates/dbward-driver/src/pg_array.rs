use crate::{JsonMapping, text_to_json};

const MAX_ARRAY_DEPTH: usize = 6;

#[derive(Debug, PartialEq)]
pub(crate) enum PgArrayParseError {
    UnsupportedBounds,
    MalformedInput,
    TooDeep,
}

/// Parse PostgreSQL array text representation into a JSON Value.
pub(crate) fn parse_pg_array(
    input: &str,
    elem_mapping: JsonMapping,
) -> Result<serde_json::Value, PgArrayParseError> {
    let input = input.trim();
    if input.starts_with('[') {
        return Err(PgArrayParseError::UnsupportedBounds);
    }
    let bytes = input.as_bytes();
    let mut pos = 0;
    let result = parse_array_at(bytes, &mut pos, elem_mapping, 0)?;
    if pos != bytes.len() {
        return Err(PgArrayParseError::MalformedInput);
    }
    Ok(result)
}

fn parse_array_at(
    bytes: &[u8],
    pos: &mut usize,
    elem_mapping: JsonMapping,
    depth: usize,
) -> Result<serde_json::Value, PgArrayParseError> {
    if depth >= MAX_ARRAY_DEPTH {
        return Err(PgArrayParseError::TooDeep);
    }
    expect_byte(bytes, pos, b'{')?;

    if peek(bytes, *pos) == Some(b'}') {
        *pos += 1;
        return Ok(serde_json::Value::Array(vec![]));
    }

    let mut elements = Vec::new();
    loop {
        let elem = if peek(bytes, *pos) == Some(b'{') {
            parse_array_at(bytes, pos, elem_mapping, depth + 1)?
        } else {
            parse_element(bytes, pos, elem_mapping)?
        };
        elements.push(elem);

        match peek(bytes, *pos) {
            Some(b',') => *pos += 1,
            Some(b'}') => {
                *pos += 1;
                break;
            }
            _ => return Err(PgArrayParseError::MalformedInput),
        }
    }
    Ok(serde_json::Value::Array(elements))
}

fn parse_element(
    bytes: &[u8],
    pos: &mut usize,
    elem_mapping: JsonMapping,
) -> Result<serde_json::Value, PgArrayParseError> {
    if peek(bytes, *pos) == Some(b'"') {
        parse_quoted_element(bytes, pos, elem_mapping)
    } else {
        parse_unquoted_element(bytes, pos, elem_mapping)
    }
}

fn parse_quoted_element(
    bytes: &[u8],
    pos: &mut usize,
    elem_mapping: JsonMapping,
) -> Result<serde_json::Value, PgArrayParseError> {
    *pos += 1; // skip opening "
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match bytes.get(*pos) {
            Some(b'\\') => {
                *pos += 1;
                match bytes.get(*pos) {
                    Some(&ch) => {
                        buf.push(ch);
                        *pos += 1;
                    }
                    None => return Err(PgArrayParseError::MalformedInput),
                }
            }
            Some(b'"') => {
                *pos += 1;
                break;
            }
            Some(&ch) => {
                buf.push(ch);
                *pos += 1;
            }
            None => return Err(PgArrayParseError::MalformedInput),
        }
    }
    let text = String::from_utf8(buf).map_err(|_| PgArrayParseError::MalformedInput)?;
    Ok(text_to_json(&text, elem_mapping))
}

fn parse_unquoted_element(
    bytes: &[u8],
    pos: &mut usize,
    elem_mapping: JsonMapping,
) -> Result<serde_json::Value, PgArrayParseError> {
    let start = *pos;
    while let Some(&ch) = bytes.get(*pos) {
        if ch == b',' || ch == b'}' {
            break;
        }
        *pos += 1;
    }
    if *pos == start {
        return Err(PgArrayParseError::MalformedInput);
    }
    let text =
        std::str::from_utf8(&bytes[start..*pos]).map_err(|_| PgArrayParseError::MalformedInput)?;
    if text == "NULL" {
        Ok(serde_json::Value::Null)
    } else {
        Ok(text_to_json(text, elem_mapping))
    }
}

fn peek(bytes: &[u8], pos: usize) -> Option<u8> {
    bytes.get(pos).copied()
}

fn expect_byte(bytes: &[u8], pos: &mut usize, expected: u8) -> Result<(), PgArrayParseError> {
    if bytes.get(*pos).copied() == Some(expected) {
        *pos += 1;
        Ok(())
    } else {
        Err(PgArrayParseError::MalformedInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_array() {
        assert_eq!(
            parse_pg_array("{}", JsonMapping::Integer).unwrap(),
            json!([])
        );
    }

    #[test]
    fn integer_array() {
        assert_eq!(
            parse_pg_array("{1,2,3}", JsonMapping::Integer).unwrap(),
            json!([1, 2, 3])
        );
    }

    #[test]
    fn text_array() {
        assert_eq!(
            parse_pg_array("{hello,world}", JsonMapping::Text).unwrap(),
            json!(["hello", "world"])
        );
    }

    #[test]
    fn null_elements() {
        assert_eq!(
            parse_pg_array("{NULL,1,2}", JsonMapping::Integer).unwrap(),
            json!([null, 1, 2])
        );
    }

    #[test]
    fn null_case_sensitive() {
        // lowercase "null" is a string, not null
        assert_eq!(
            parse_pg_array("{null}", JsonMapping::Text).unwrap(),
            json!(["null"])
        );
    }

    #[test]
    fn quoted_null_is_string() {
        assert_eq!(
            parse_pg_array("{\"NULL\"}", JsonMapping::Text).unwrap(),
            json!(["NULL"])
        );
    }

    #[test]
    fn quoted_with_comma() {
        assert_eq!(
            parse_pg_array("{\"with,comma\",\"plain\"}", JsonMapping::Text).unwrap(),
            json!(["with,comma", "plain"])
        );
    }

    #[test]
    fn quoted_with_escaped_quote() {
        assert_eq!(
            parse_pg_array("{\"with\\\"quote\"}", JsonMapping::Text).unwrap(),
            json!(["with\"quote"])
        );
    }

    #[test]
    fn quoted_with_backslash() {
        assert_eq!(
            parse_pg_array("{\"with\\\\backslash\"}", JsonMapping::Text).unwrap(),
            json!(["with\\backslash"])
        );
    }

    #[test]
    fn quoted_empty_string() {
        assert_eq!(
            parse_pg_array("{\"\"}", JsonMapping::Text).unwrap(),
            json!([""])
        );
    }

    #[test]
    fn quoted_braces() {
        assert_eq!(
            parse_pg_array("{\"{x}\"}", JsonMapping::Text).unwrap(),
            json!(["{x}"])
        );
    }

    #[test]
    fn multidimensional() {
        assert_eq!(
            parse_pg_array("{{1,2},{3,4}}", JsonMapping::Integer).unwrap(),
            json!([[1, 2], [3, 4]])
        );
    }

    #[test]
    fn multidimensional_with_null() {
        assert_eq!(
            parse_pg_array("{{NULL,1},{2,3}}", JsonMapping::Integer).unwrap(),
            json!([[null, 1], [2, 3]])
        );
    }

    #[test]
    fn bool_array() {
        assert_eq!(
            parse_pg_array("{t,f,t}", JsonMapping::Bool).unwrap(),
            json!([true, false, true])
        );
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn float_array() {
        assert_eq!(
            parse_pg_array("{3.14,2.71}", JsonMapping::Float).unwrap(),
            json!([3.14, 2.71])
        );
    }

    #[test]
    fn json_array() {
        assert_eq!(
            parse_pg_array("{\"{}\"}", JsonMapping::Json).unwrap(),
            json!([{}])
        );
    }

    #[test]
    fn json_array_nested() {
        assert_eq!(
            parse_pg_array("{\"\\{\\\"a\\\":1\\}\"}", JsonMapping::Json).unwrap(),
            json!([{"a": 1}])
        );
    }

    #[test]
    fn bytea_array() {
        assert_eq!(
            parse_pg_array("{\"\\\\xDEAD\",\"\\\\xBEEF\"}", JsonMapping::Binary).unwrap(),
            json!(["\\xDEAD", "\\xBEEF"])
        );
    }

    #[test]
    fn utf8_text() {
        assert_eq!(
            parse_pg_array("{\"あいう\",\"日本語\"}", JsonMapping::Text).unwrap(),
            json!(["あいう", "日本語"])
        );
    }

    #[test]
    fn utf8_unquoted() {
        assert_eq!(
            parse_pg_array("{café,naïve}", JsonMapping::Text).unwrap(),
            json!(["café", "naïve"])
        );
    }

    #[test]
    fn unsupported_bounds() {
        assert_eq!(
            parse_pg_array("[1:3]={1,2,3}", JsonMapping::Integer),
            Err(PgArrayParseError::UnsupportedBounds)
        );
    }

    #[test]
    fn malformed_empty() {
        assert_eq!(
            parse_pg_array("", JsonMapping::Text),
            Err(PgArrayParseError::MalformedInput)
        );
    }

    #[test]
    fn malformed_unclosed() {
        assert_eq!(
            parse_pg_array("{1,2", JsonMapping::Integer),
            Err(PgArrayParseError::MalformedInput)
        );
    }

    #[test]
    fn malformed_no_brace() {
        assert_eq!(
            parse_pg_array("1,2,3", JsonMapping::Integer),
            Err(PgArrayParseError::MalformedInput)
        );
    }

    #[test]
    fn too_deep() {
        // 7 levels of nesting
        assert_eq!(
            parse_pg_array("{{{{{{{1}}}}}}}", JsonMapping::Integer),
            Err(PgArrayParseError::TooDeep)
        );
    }

    #[test]
    fn single_null() {
        assert_eq!(
            parse_pg_array("{NULL}", JsonMapping::Integer).unwrap(),
            json!([null])
        );
    }

    #[test]
    fn trailing_content_is_error() {
        assert_eq!(
            parse_pg_array("{1,2}extra", JsonMapping::Integer),
            Err(PgArrayParseError::MalformedInput)
        );
    }
}
