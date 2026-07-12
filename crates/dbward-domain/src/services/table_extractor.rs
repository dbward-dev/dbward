use sqlparser::ast::{
    FromTable, ObjectName, Query, SetExpr, Statement, TableFactor, visit_relations,
};
use std::collections::{HashMap, HashSet};

/// A reference to a table found in SQL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableRef {
    pub schema: Option<String>,
    pub name: String,
}

impl TableRef {
    pub fn bare_name(&self) -> &str {
        &self.name
    }
}

/// Returns true if any statement is a DELETE (including data-modifying CTEs).
pub fn has_delete_statement(statements: &[Statement]) -> bool {
    statements.iter().any(|s| match s {
        Statement::Delete(_) => true,
        Statement::Query(q) => query_contains_delete(q),
        _ => false,
    })
}

fn query_contains_delete(query: &Query) -> bool {
    // Check if the query body itself is a DELETE
    if matches!(query.body.as_ref(), SetExpr::Delete(_)) {
        return true;
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if matches!(cte.query.body.as_ref(), SetExpr::Delete(_)) {
                return true;
            }
            if query_contains_delete(&cte.query) {
                return true;
            }
        }
    }
    false
}

/// Extract only the tables that are actual targets of DELETE/TRUNCATE mutations.
/// Does NOT include tables referenced in JOINs, subqueries, or USING clauses.
pub fn extract_delete_targets(statements: &[Statement]) -> Vec<TableRef> {
    let mut targets = HashSet::new();
    for stmt in statements {
        collect_delete_targets_from_stmt(stmt, &mut targets);
    }
    targets.into_iter().collect()
}

fn collect_delete_targets_from_stmt(stmt: &Statement, targets: &mut HashSet<TableRef>) {
    match stmt {
        Statement::Delete(del) => {
            let tables_with_joins = match &del.from {
                FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
            };
            // Build alias→real table map from FROM clause
            let mut alias_map: HashMap<String, TableRef> = HashMap::new();
            for twj in tables_with_joins {
                if let TableFactor::Table { name, alias, .. } = &twj.relation {
                    let real_ref = object_name_to_ref(name);
                    if let Some(a) = alias {
                        alias_map.insert(a.name.value.clone(), real_ref.clone());
                    }
                }
                for join in &twj.joins {
                    if let TableFactor::Table { name, alias, .. } = &join.relation {
                        let real_ref = object_name_to_ref(name);
                        if let Some(a) = alias {
                            alias_map.insert(a.name.value.clone(), real_ref);
                        }
                    }
                }
            }
            // Standard DELETE: first relation in FROM is the target (when no explicit del.tables)
            #[allow(clippy::collapsible_if)]
            if del.tables.is_empty() {
                if let Some(first) = tables_with_joins.first() {
                    if let TableFactor::Table { name, .. } = &first.relation {
                        targets.insert(object_name_to_ref(name));
                    }
                }
            }
            // MySQL multi-table DELETE: del.tables contains table names or aliases
            for t in &del.tables {
                let ref_name = object_name_to_ref(t);
                if let Some(real) = alias_map.get(&ref_name.name) {
                    targets.insert(real.clone());
                } else {
                    targets.insert(ref_name);
                }
            }
        }
        Statement::Truncate(trunc) => {
            for table_target in &trunc.table_names {
                targets.insert(object_name_to_ref(&table_target.name));
            }
        }
        // Data-modifying CTE: WITH x AS (DELETE ...) SELECT ...
        Statement::Query(query) => {
            collect_delete_targets_from_query(query, targets);
        }
        _ => {}
    }
}

fn collect_delete_targets_from_query(query: &Query, targets: &mut HashSet<TableRef>) {
    // Check if the query body itself is a DELETE
    if let SetExpr::Delete(del_stmt) = query.body.as_ref() {
        collect_delete_targets_from_stmt(del_stmt, targets);
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            // CTE body might be a DELETE wrapped in SetExpr::Delete(Box<Statement>)
            if let SetExpr::Delete(del_stmt) = cte.query.body.as_ref() {
                collect_delete_targets_from_stmt(del_stmt, targets);
            }
            // Recurse into sub-CTEs
            collect_delete_targets_from_query(&cte.query, targets);
        }
    }
}

/// Extract table references from pre-parsed AST statements.
/// Uses sqlparser's built-in visit_relations for comprehensive coverage.
/// CTE names are excluded via post-processing.
pub fn extract_tables(statements: &[Statement]) -> Vec<TableRef> {
    let mut tables = HashSet::new();
    let mut cte_names = HashSet::new();

    // Collect CTE names
    for stmt in statements {
        collect_cte_names(stmt, &mut cte_names);
    }

    // Use sqlparser's visitor to find all relation references
    for stmt in statements {
        let _ = visit_relations(stmt, |relation| {
            let table_ref = object_name_to_ref(relation);
            tables.insert(table_ref);
            std::ops::ControlFlow::<()>::Continue(())
        });
    }

    // Remove CTE names
    tables
        .into_iter()
        .filter(|t| !cte_names.contains(&t.name.to_lowercase()))
        .collect()
}

fn collect_cte_names(stmt: &Statement, cte_names: &mut HashSet<String>) {
    // Use visit_expressions approach won't work for CTEs; manually check common patterns
    match stmt {
        Statement::Query(q) => collect_cte_names_from_query(q, cte_names),
        Statement::Insert(ins) => {
            if let Some(src) = &ins.source {
                collect_cte_names_from_query(src.as_ref(), cte_names);
            }
        }
        _ => {}
    }
}

fn collect_cte_names_from_query(query: &Query, cte_names: &mut HashSet<String>) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            cte_names.insert(cte.alias.name.value.to_lowercase());
            collect_cte_names_from_query(&cte.query, cte_names);
        }
    }
    // Check subqueries in body
    if let SetExpr::Query(sub) = query.body.as_ref() {
        collect_cte_names_from_query(sub, cte_names);
    }
}

fn object_name_to_ref(name: &ObjectName) -> TableRef {
    let parts: Vec<&str> = name
        .0
        .iter()
        .filter_map(|part| part.as_ident().map(|id| id.value.as_str()))
        .collect();

    match parts.len() {
        0 => TableRef {
            schema: None,
            name: name.to_string(),
        },
        1 => TableRef {
            schema: None,
            name: parts[0].to_string(),
        },
        2 => TableRef {
            schema: Some(parts[0].to_string()),
            name: parts[1].to_string(),
        },
        _ => TableRef {
            schema: Some(parts[parts.len() - 2].to_string()),
            name: parts[parts.len() - 1].to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::classification::Dialect;
    use crate::services::sql_parser;

    fn extract(sql: &str) -> Vec<TableRef> {
        let stmts = sql_parser::parse_statements(sql, Dialect::PostgreSql).unwrap();
        let mut result = extract_tables(&stmts);
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    #[test]
    fn simple_select() {
        let tables = extract("SELECT * FROM orders");
        assert_eq!(
            tables,
            vec![TableRef {
                schema: None,
                name: "orders".into()
            }]
        );
    }

    #[test]
    fn join() {
        let tables = extract("SELECT * FROM orders o JOIN users u ON o.user_id = u.id");
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "orders".into()
        }));
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "users".into()
        }));
    }

    #[test]
    fn cte_excluded() {
        let tables = extract("WITH cte AS (SELECT * FROM orders) SELECT * FROM cte");
        assert_eq!(
            tables,
            vec![TableRef {
                schema: None,
                name: "orders".into()
            }]
        );
    }

    #[test]
    fn subquery() {
        let tables = extract("SELECT * FROM (SELECT * FROM orders) sub");
        assert_eq!(
            tables,
            vec![TableRef {
                schema: None,
                name: "orders".into()
            }]
        );
    }

    #[test]
    fn schema_qualified() {
        let tables = extract("SELECT * FROM public.orders");
        assert_eq!(
            tables,
            vec![TableRef {
                schema: Some("public".into()),
                name: "orders".into()
            }]
        );
    }

    #[test]
    fn insert_select() {
        let tables = extract("INSERT INTO target SELECT * FROM source");
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "source".into()
        }));
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "target".into()
        }));
    }

    #[test]
    fn delete_simple() {
        let tables = extract("DELETE FROM orders WHERE id = 1");
        assert_eq!(
            tables,
            vec![TableRef {
                schema: None,
                name: "orders".into()
            }]
        );
    }

    #[test]
    fn where_subquery() {
        let tables = extract(
            "SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE active = true)",
        );
        assert_eq!(tables.len(), 2);
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "orders".into()
        }));
        assert!(tables.contains(&TableRef {
            schema: None,
            name: "users".into()
        }));
    }

    #[test]
    fn deduplication() {
        let tables = extract("SELECT * FROM orders JOIN orders ON true");
        assert_eq!(tables.len(), 1);
    }

    // --- extract_delete_targets tests ---

    fn delete_targets(sql: &str) -> Vec<TableRef> {
        let stmts = sql_parser::parse_statements(sql, Dialect::PostgreSql).unwrap();
        let mut result = extract_delete_targets(&stmts);
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    fn delete_targets_mysql(sql: &str) -> Vec<TableRef> {
        let stmts = sql_parser::parse_statements(sql, Dialect::MySql).unwrap();
        let mut result = extract_delete_targets(&stmts);
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    #[test]
    fn delete_target_simple() {
        let targets = delete_targets("DELETE FROM users WHERE id = 1");
        assert_eq!(
            targets,
            vec![TableRef {
                schema: None,
                name: "users".into()
            }]
        );
    }

    #[test]
    fn delete_target_excludes_subquery_tables() {
        let targets = delete_targets(
            "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE active = false)",
        );
        assert_eq!(
            targets,
            vec![TableRef {
                schema: None,
                name: "sessions".into()
            }]
        );
    }

    #[test]
    fn delete_target_schema_qualified() {
        let targets = delete_targets("DELETE FROM public.users WHERE id = 1");
        assert_eq!(
            targets,
            vec![TableRef {
                schema: Some("public".into()),
                name: "users".into()
            }]
        );
    }

    #[test]
    fn delete_target_mysql_multi_table_alias() {
        let targets = delete_targets_mysql(
            "DELETE u FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total = 0",
        );
        assert_eq!(
            targets,
            vec![TableRef {
                schema: None,
                name: "users".into()
            }]
        );
    }

    #[test]
    fn truncate_targets() {
        let targets = delete_targets("TRUNCATE TABLE orders, items");
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&TableRef {
            schema: None,
            name: "items".into()
        }));
        assert!(targets.contains(&TableRef {
            schema: None,
            name: "orders".into()
        }));
    }

    #[test]
    fn update_returns_empty() {
        let targets = delete_targets("UPDATE users SET name = 'x' WHERE id = 1");
        assert!(targets.is_empty());
    }

    #[test]
    fn select_returns_empty() {
        let targets = delete_targets("SELECT * FROM users");
        assert!(targets.is_empty());
    }

    // --- has_delete_statement tests ---

    #[test]
    fn has_delete_true_for_delete() {
        let stmts =
            sql_parser::parse_statements("DELETE FROM users WHERE id = 1", Dialect::PostgreSql)
                .unwrap();
        assert!(has_delete_statement(&stmts));
    }

    #[test]
    fn has_delete_false_for_update() {
        let stmts =
            sql_parser::parse_statements("UPDATE users SET x = 1", Dialect::PostgreSql).unwrap();
        assert!(!has_delete_statement(&stmts));
    }

    #[test]
    fn has_delete_false_for_truncate() {
        let stmts =
            sql_parser::parse_statements("TRUNCATE TABLE users", Dialect::PostgreSql).unwrap();
        assert!(!has_delete_statement(&stmts));
    }

    #[test]
    fn has_delete_false_for_select() {
        let stmts = sql_parser::parse_statements("SELECT 1", Dialect::PostgreSql).unwrap();
        assert!(!has_delete_statement(&stmts));
    }

    #[test]
    fn has_delete_true_for_cte_with_delete_body() {
        // WITH ... DELETE is parsed as Statement::Query with body=SetExpr::Delete
        let sql = "WITH deleted AS (DELETE FROM users WHERE active = false RETURNING id) SELECT * FROM deleted";
        let stmts = sql_parser::parse_statements(sql, Dialect::PostgreSql).unwrap();
        assert!(has_delete_statement(&stmts));
    }

    #[test]
    fn extract_delete_targets_from_cte_body() {
        let sql = "WITH deleted AS (DELETE FROM users WHERE active = false RETURNING id) SELECT * FROM deleted";
        let stmts = sql_parser::parse_statements(sql, Dialect::PostgreSql).unwrap();
        let targets = extract_delete_targets(&stmts);
        assert!(targets.contains(&TableRef {
            schema: None,
            name: "users".into()
        }));
    }

    #[test]
    fn delete_target_mysql_multi_from_alias() {
        // MySQL: DELETE u, o FROM users u, orders o WHERE u.id = o.user_id
        let targets =
            delete_targets_mysql("DELETE u, o FROM users u, orders o WHERE u.id = o.user_id");
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&TableRef {
            schema: None,
            name: "users".into()
        }));
        assert!(targets.contains(&TableRef {
            schema: None,
            name: "orders".into()
        }));
    }
}
