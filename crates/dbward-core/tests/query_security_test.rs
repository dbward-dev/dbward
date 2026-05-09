//! Adversarial tests for query classification bypass attempts.
use dbward_core::{QueryType, classify_query, classify_query_mysql};

// === Comment-based obfuscation ===

#[test]
fn comment_hiding_ddl() {
    // Try to hide DROP in a comment trick
    assert!(classify_query("SELECT 1; /* */ DROP TABLE users").is_err());
}

#[test]
fn inline_comment_between_keywords() {
    // DELETE with inline comments
    let r = classify_query("DE/**/LETE FROM users");
    // sqlparser should either parse this as DELETE (DML) or fail
    assert!(r.is_err() || matches!(r.unwrap(), QueryType::Delete));
}

#[test]
fn nested_comments_pg() {
    // PostgreSQL supports nested comments
    let r = classify_query("/* /* nested */ */ SELECT 1");
    assert!(r.is_ok());
}

// === Dollar-quoted strings (PostgreSQL) ===

#[test]
fn dollar_quoted_string_not_executed() {
    // Dollar-quoted string containing dangerous SQL - should be just a string literal
    let r = classify_query("SELECT $$DROP TABLE users$$");
    assert_eq!(r.unwrap(), QueryType::Select);
}

#[test]
fn do_block_rejected() {
    // DO blocks execute arbitrary PL/pgSQL - must be rejected
    let r = classify_query("DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$");
    assert!(r.is_err());
}

// === COPY ... FROM PROGRAM ===

#[test]
fn copy_from_program_is_dml() {
    let r = classify_query("COPY users FROM PROGRAM 'cat /etc/passwd'");
    // Should be DML or rejected (both are safe)
    assert!(r.is_err() || matches!(r.unwrap(), QueryType::Dml));
}

// === CREATE FUNCTION disguised ===

#[test]
fn create_function_rejected() {
    assert!(classify_query("CREATE FUNCTION evil() RETURNS void AS $$ BEGIN DELETE FROM users; END $$ LANGUAGE plpgsql").is_err());
}

// === SET search_path attack ===

#[test]
fn set_search_path_rejected() {
    assert!(classify_query("SET search_path TO evil_schema, public").is_err());
}

#[test]
fn set_session_authorization_rejected() {
    assert!(classify_query("SET SESSION AUTHORIZATION 'postgres'").is_err());
}

#[test]
fn set_role_rejected() {
    assert!(classify_query("SET ROLE postgres").is_err());
}

// === Multi-statement escalation ===

#[test]
fn select_then_drop_rejected() {
    assert!(classify_query("SELECT 1; DROP TABLE users").is_err());
}

#[test]
fn select_then_create_rejected() {
    assert!(classify_query("SELECT 1; CREATE TABLE evil (id int)").is_err());
}

#[test]
fn select_then_grant_rejected() {
    assert!(classify_query("SELECT 1; GRANT ALL ON users TO evil").is_err());
}

// === Dangerous functions with schema qualification ===

#[test]
fn schema_qualified_dangerous_function() {
    // pg_catalog.pg_sleep should still be caught
    let r = classify_query("SELECT pg_catalog.pg_sleep(999)");
    assert_eq!(r.unwrap(), QueryType::Dml);
}

#[test]
fn schema_qualified_dblink() {
    let r = classify_query("SELECT public.dblink_exec('connstr', 'DROP TABLE t')");
    assert_eq!(r.unwrap(), QueryType::Dml);
}

// === Unicode/encoding attacks ===

#[test]
fn unicode_null_byte_rejected() {
    assert!(classify_query("SELECT 1\0; DROP TABLE users").is_err());
}

#[test]
fn unicode_semicolon_lookalike() {
    // Greek question mark (;) U+037E looks like semicolon
    let r = classify_query("SELECT 1\u{037E} DROP TABLE users");
    // Should either fail to parse or treat as single SELECT
    assert!(r.is_err() || r.unwrap() == QueryType::Select);
}

#[test]
fn backslash_escape_attempt() {
    // Try to break out of a string with backslash
    let r = classify_query(r"SELECT '\'; DROP TABLE users; --'");
    // sqlparser should handle this as a string literal or fail
    assert!(r.is_err() || r.unwrap() == QueryType::Select);
}

// === Parser edge cases ===

#[test]
fn extremely_long_identifier() {
    let long_name = "a".repeat(10000);
    let sql = format!("SELECT * FROM {long_name}");
    // Should not panic or hang
    let _ = classify_query(&sql);
}

#[test]
fn deeply_nested_subquery() {
    let mut sql = "SELECT 1".to_string();
    for _ in 0..50 {
        sql = format!("SELECT * FROM ({sql}) AS t");
    }
    // Should not stack overflow
    let r = classify_query(&sql);
    assert!(r.is_ok() || r.is_err()); // just don't panic
}

#[test]
fn empty_statements_semicolons() {
    // Multiple semicolons
    let r = classify_query(";;;");
    assert!(r.is_err());
}

// === Writable CTE bypass attempts ===

#[test]
fn writable_cte_insert() {
    let sql = "WITH ins AS (INSERT INTO users(name) VALUES ('x') RETURNING *) SELECT * FROM ins";
    let r = classify_query(sql);
    assert!(matches!(r.unwrap(), QueryType::Dml | QueryType::Insert));
}

#[test]
fn writable_cte_update() {
    let sql = "WITH upd AS (UPDATE users SET name='x' RETURNING *) SELECT * FROM upd";
    let r = classify_query(sql);
    assert!(matches!(r.unwrap(), QueryType::Dml | QueryType::Update));
}

// === SELECT INTO (creates a table) ===

#[test]
fn select_into_is_dml() {
    let r = classify_query("SELECT * INTO new_table FROM users");
    assert_eq!(r.unwrap(), QueryType::Dml);
}

// === EXECUTE (prepared statement - unknown content) ===

#[test]
fn execute_prepared_is_dml() {
    assert_eq!(classify_query("EXECUTE my_plan").unwrap(), QueryType::Dml);
}

#[test]
fn execute_with_params_is_dml() {
    assert_eq!(
        classify_query("EXECUTE my_plan(1, 'x')").unwrap(),
        QueryType::Dml
    );
}

// === MySQL-specific ===

#[test]
fn mysql_load_data_rejected() {
    let r = classify_query_mysql("LOAD DATA INFILE '/etc/passwd' INTO TABLE t");
    // Should be rejected or DML
    assert!(r.is_err() || matches!(r.unwrap(), QueryType::Dml));
}

#[test]
fn mysql_into_outfile_is_dml() {
    let r = classify_query_mysql("SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'");
    // INTO makes it DML
    assert!(r.is_err() || matches!(r.unwrap(), QueryType::Dml));
}
