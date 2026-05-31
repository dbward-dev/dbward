use sqlparser::ast::{ObjectName, Query, SetExpr, Statement, visit_relations};
use std::collections::HashSet;

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
}
