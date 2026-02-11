//! Minimal JSON string field extraction (no serde dependency).

/// Extract a JSON string field value by key from a flat or nested JSON string.
///
/// Searches for `"<key>"` followed by `:` and a quoted string value.
/// Returns the inner string (without quotes).
pub(crate) fn extract_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{key}\"");
    let idx = json.find(&search)?;
    let after_key = &json[idx + search.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    let after_quote = after_ws.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(&after_quote[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_nested() {
        let json =
            r#"{"data":{"request_swap":{"request":{"inbound_transfer":{"spark_id":"abc-123"}}}}}"#;
        assert_eq!(extract_string_field(json, "spark_id"), Some("abc-123"));
    }

    #[test]
    fn extract_missing() {
        assert_eq!(extract_string_field(r#"{"data":{}}"#, "spark_id"), None);
    }

    #[test]
    fn extract_session_token() {
        let json = r#"{"data":{"verify_challenge":{"session_token":"tok123"}}}"#;
        assert_eq!(extract_string_field(json, "session_token"), Some("tok123"));
    }
}
