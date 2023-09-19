// Copyright 2021 Datafuse Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::Display;
use std::fmt::Formatter;

use common_exception::Span;

use crate::ast::write_comma_separated_list;
use crate::ast::write_dot_separated_list;
use crate::ast::ColumnID;
use crate::ast::Expr;
use crate::ast::FileLocation;
use crate::ast::Hint;
use crate::ast::Identifier;
use crate::ast::SelectStageOptions;
use crate::ast::WindowDefinition;

/// Root node of a query tree
#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub span: Span,
    // With clause, common table expression
    pub with: Option<With>,
    // Set operator: SELECT or UNION / EXCEPT / INTERSECT
    pub body: SetExpr,

    // The following clauses can only appear in top level of a subquery/query
    // `ORDER BY` clause
    pub order_by: Vec<OrderByExpr>,
    // `LIMIT` clause
    pub limit: Vec<Expr>,
    // `OFFSET` expr
    pub offset: Option<Expr>,

    // If ignore the result (not output).
    pub ignore_result: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct With {
    pub span: Span,
    pub recursive: bool,
    pub ctes: Vec<CTE>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CTE {
    pub span: Span,
    pub alias: TableAlias,
    pub materialized: bool,
    pub query: Box<Query>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SetOperation {
    pub span: Span,
    pub op: SetOperator,
    pub all: bool,
    pub left: Box<SetExpr>,
    pub right: Box<SetExpr>,
}

/// A subquery represented with `SELECT` statement
#[derive(Debug, Clone, PartialEq)]
pub struct SelectStmt {
    pub span: Span,
    pub hints: Option<Hint>,
    pub distinct: bool,
    // Result set of current subquery
    pub select_list: Vec<SelectTarget>,
    // `FROM` clause, a list of table references.
    // The table references split by `,` will be joined with cross join,
    // and the result set is union of the joined tables by default.
    pub from: Vec<TableReference>,
    // `WHERE` clause
    pub selection: Option<Expr>,
    // `GROUP BY` clause
    pub group_by: Option<GroupBy>,
    // `HAVING` clause
    pub having: Option<Expr>,
    // `WINDOW` clause
    pub window_list: Option<Vec<WindowDefinition>>,
}

/// Group by Clause.
#[derive(Debug, Clone, PartialEq)]
pub enum GroupBy {
    /// GROUP BY expr [, expr]*
    Normal(Vec<Expr>),
    /// GROUP By ALL
    All,
    /// GROUP BY GROUPING SETS ( GroupSet [, GroupSet]* )
    ///
    /// GroupSet := (expr [, expr]*) | expr
    GroupingSets(Vec<Vec<Expr>>),
    /// GROUP BY CUBE ( expr [, expr]* )
    Cube(Vec<Expr>),
    /// GROUP BY ROLLUP ( expr [, expr]* )
    Rollup(Vec<Expr>),
}

/// A relational set expression, like `SELECT ... FROM ... {UNION|EXCEPT|INTERSECT} SELECT ... FROM ...`
#[derive(Debug, Clone, PartialEq)]
pub enum SetExpr {
    Select(Box<SelectStmt>),
    Query(Box<Query>),
    // UNION/EXCEPT/INTERSECT operator
    SetOperation(Box<SetOperation>),
    // Values clause
    Values { span: Span, values: Vec<Vec<Expr>> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetOperator {
    Union,
    Except,
    Intersect,
}

/// `ORDER BY` clause
#[derive(Debug, Clone, PartialEq)]
pub struct OrderByExpr {
    pub expr: Expr,
    // Optional `ASC` or `DESC`
    pub asc: Option<bool>,
    // Optional `NULLS FIRST` or `NULLS LAST`
    pub nulls_first: Option<bool>,
}

/// One item of the comma-separated list following `SELECT`
#[derive(Debug, Clone, PartialEq)]
pub enum SelectTarget {
    // Expression with alias, e.g. `SELECT b AS a, a+1 AS b FROM t`
    AliasedExpr {
        expr: Box<Expr>,
        alias: Option<Identifier>,
    },

    // Qualified name, e.g. `SELECT t.a, t.* exclude t.a FROM t`.
    // For simplicity, wildcard is involved.
    QualifiedName {
        qualified: QualifiedName,
        exclude: Option<Vec<ColumnID>>,
    },
}

impl SelectTarget {
    pub fn is_star(&self) -> bool {
        match self {
            SelectTarget::AliasedExpr { .. } => false,
            SelectTarget::QualifiedName { qualified, .. } => {
                matches!(qualified.last(), Some(Indirection::Star(_)))
            }
        }
    }

    pub fn exclude(&mut self, exclude: Vec<ColumnID>) {
        match self {
            SelectTarget::AliasedExpr { .. } => unreachable!(),
            SelectTarget::QualifiedName { exclude: e, .. } => {
                *e = Some(exclude);
            }
        }
    }

    pub fn has_window(&self) -> bool {
        match self {
            SelectTarget::AliasedExpr { expr, .. } => match expr.as_ref() {
                Expr::FunctionCall { window, .. } => window.is_some(),
                _ => false,
            },
            SelectTarget::QualifiedName { .. } => false,
        }
    }

    pub fn function_call_name(&self) -> Option<String> {
        match self {
            SelectTarget::AliasedExpr {  expr, .. } => match expr.as_ref() {
                Expr::FunctionCall { name, window, .. } if window.is_none() => {
                    Some(name.name.to_lowercase())
                }
                _ => None,
            },
            SelectTarget::QualifiedName { .. } => None,
        }
    }
}

pub type QualifiedName = Vec<Indirection>;

/// Indirection of a select result, like a part of `db.table.column`.
/// Can be a database name, table name, field name or wildcard star(`*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Indirection {
    // Field name
    Identifier(Identifier),
    // Wildcard star
    Star(Span),
}

/// Time Travel specification
#[derive(Debug, Clone, PartialEq)]
pub enum TimeTravelPoint {
    Snapshot(String),
    Timestamp(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pivot {
    pub aggregate: Expr,
    pub value_column: Identifier,
    pub values: Vec<Expr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Unpivot {
    pub value_column: Identifier,
    pub column_name: Identifier,
    pub names: Vec<Identifier>,
}

/// A table name or a parenthesized subquery with an optional alias
#[derive(Debug, Clone, PartialEq)]
pub enum TableReference {
    // Table name
    Table {
        span: Span,
        catalog: Option<Identifier>,
        database: Option<Identifier>,
        table: Identifier,
        alias: Option<TableAlias>,
        travel_point: Option<TimeTravelPoint>,
        pivot: Option<Box<Pivot>>,
        unpivot: Option<Box<Unpivot>>,
    },
    // `TABLE(expr)[ AS alias ]`
    TableFunction {
        span: Span,
        name: Identifier,
        params: Vec<Expr>,
        named_params: Vec<(String, Expr)>,
        alias: Option<TableAlias>,
    },
    // Derived table, which can be a subquery or joined tables or combination of them
    Subquery {
        span: Span,
        subquery: Box<Query>,
        alias: Option<TableAlias>,
    },
    Join {
        span: Span,
        join: Join,
    },
    Location {
        span: Span,
        location: FileLocation,
        options: SelectStageOptions,
        alias: Option<TableAlias>,
    },
}

impl TableReference {
    pub fn pivot(&self) -> Option<&Pivot> {
        match self {
            TableReference::Table { pivot, .. } => pivot.as_ref().map(|b| b.as_ref()),
            _ => None,
        }
    }

    pub fn unpivot(&self) -> Option<&Unpivot> {
        match self {
            TableReference::Table { unpivot, .. } => unpivot.as_ref().map(|b| b.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableAlias {
    pub name: Identifier,
    pub columns: Vec<Identifier>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Join {
    pub op: JoinOperator,
    pub condition: JoinCondition,
    pub left: Box<TableReference>,
    pub right: Box<TableReference>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinOperator {
    Inner,
    // Outer joins can not work with `JoinCondition::None`
    LeftOuter,
    RightOuter,
    FullOuter,
    LeftSemi,
    LeftAnti,
    RightSemi,
    RightAnti,
    // CrossJoin can only work with `JoinCondition::None`
    CrossJoin,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JoinCondition {
    On(Box<Expr>),
    Using(Vec<Identifier>),
    Natural,
    None,
}

impl SetExpr {
    pub fn span(&self) -> Span {
        match self {
            SetExpr::Select(stmt) => stmt.span,
            SetExpr::Query(query) => query.span,
            SetExpr::SetOperation(op) => op.span,
            SetExpr::Values { span, .. } => *span,
        }
    }

    pub fn into_query(self) -> Query {
        match self {
            SetExpr::Query(query) => *query,
            _ => Query {
                span: self.span(),
                with: None,
                body: self,
                order_by: vec![],
                limit: vec![],
                offset: None,
                ignore_result: false,
            },
        }
    }
}

impl Display for OrderByExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.expr)?;
        if let Some(asc) = self.asc {
            if asc {
                write!(f, " ASC")?;
            } else {
                write!(f, " DESC")?;
            }
        }
        if let Some(nulls_first) = self.nulls_first {
            if nulls_first {
                write!(f, " NULLS FIRST")?;
            } else {
                write!(f, " NULLS LAST")?;
            }
        }
        Ok(())
    }
}

impl Display for TableAlias {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.name)?;
        if !self.columns.is_empty() {
            write!(f, "(")?;
            write_comma_separated_list(f, &self.columns)?;
            write!(f, ")")?;
        }
        Ok(())
    }
}

impl Display for Pivot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PIVOT({} FOR {} IN (", self.aggregate, self.value_column)?;
        write_comma_separated_list(f, &self.values)?;
        write!(f, "))")?;
        Ok(())
    }
}

impl Display for Unpivot {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UNPIVOT({} FOR {} IN (",
            self.value_column, self.column_name
        )?;
        write_comma_separated_list(f, &self.names)?;
        write!(f, "))")?;
        Ok(())
    }
}

impl Display for TableReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TableReference::Table {
                span: _,
                catalog,
                database,
                table,
                alias,
                travel_point,
                pivot,
                unpivot,
            } => {
                write_dot_separated_list(
                    f,
                    catalog.iter().chain(database.iter()).chain(Some(table)),
                )?;

                if let Some(TimeTravelPoint::Snapshot(sid)) = travel_point {
                    write!(f, " AT (SNAPSHOT => {sid})")?;
                }

                if let Some(TimeTravelPoint::Timestamp(ts)) = travel_point {
                    write!(f, " AT (TIMESTAMP => {ts})")?;
                }

                if let Some(alias) = alias {
                    write!(f, " AS {alias}")?;
                }
                if let Some(pivot) = pivot {
                    write!(f, " {pivot}")?;
                }

                if let Some(unpivot) = unpivot {
                    write!(f, " {unpivot}")?;
                }
            }
            TableReference::TableFunction {
                span: _,
                name,
                params,
                named_params,
                alias,
            } => {
                write!(f, "{name}(")?;
                write_comma_separated_list(f, params)?;
                if !params.is_empty() && !named_params.is_empty() {
                    write!(f, ",")?;
                }
                for (i, (k, v)) in named_params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{k}=>{v}")?;
                }
                write!(f, ")")?;
                if let Some(alias) = alias {
                    write!(f, " AS {alias}")?;
                }
            }
            TableReference::Subquery {
                span: _,
                subquery,
                alias,
            } => {
                write!(f, "({subquery})")?;
                if let Some(alias) = alias {
                    write!(f, " AS {alias}")?;
                }
            }
            TableReference::Join { span: _, join } => {
                write!(f, "{}", join.left)?;
                if join.condition == JoinCondition::Natural {
                    write!(f, " NATURAL")?;
                }
                match join.op {
                    JoinOperator::Inner => {
                        write!(f, " INNER JOIN")?;
                    }
                    JoinOperator::LeftOuter => {
                        write!(f, " LEFT OUTER JOIN")?;
                    }
                    JoinOperator::RightOuter => {
                        write!(f, " RIGHT OUTER JOIN")?;
                    }
                    JoinOperator::FullOuter => {
                        write!(f, " FULL OUTER JOIN")?;
                    }
                    JoinOperator::LeftSemi => {
                        write!(f, " LEFT SEMI JOIN")?;
                    }
                    JoinOperator::RightSemi => {
                        write!(f, " RIGHT SEMI JOIN")?;
                    }
                    JoinOperator::LeftAnti => {
                        write!(f, " LEFT ANTI JOIN")?;
                    }
                    JoinOperator::RightAnti => {
                        write!(f, " RIGHT ANTI JOIN")?;
                    }
                    JoinOperator::CrossJoin => {
                        write!(f, " CROSS JOIN")?;
                    }
                }
                write!(f, " {}", join.right)?;
                match &join.condition {
                    JoinCondition::On(expr) => {
                        write!(f, " ON {expr}")?;
                    }
                    JoinCondition::Using(idents) => {
                        write!(f, " USING(")?;
                        write_comma_separated_list(f, idents)?;
                        write!(f, ")")?;
                    }
                    _ => {}
                }
            }
            TableReference::Location {
                span: _,
                location,
                options,
                alias,
            } => {
                write!(f, "{location}")?;
                if !options.is_empty() {
                    write!(f, "{options}")?;
                }
                if let Some(alias) = alias {
                    write!(f, " AS {alias}")?;
                }
            }
        }
        Ok(())
    }
}

impl Display for Indirection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Indirection::Identifier(ident) => {
                write!(f, "{ident}")?;
            }
            Indirection::Star(_) => {
                write!(f, "*")?;
            }
        }
        Ok(())
    }
}

impl Display for SelectTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectTarget::AliasedExpr { expr, alias } => {
                write!(f, "{expr}")?;
                if let Some(ident) = alias {
                    write!(f, " AS {ident}")?;
                }
            }
            SelectTarget::QualifiedName { qualified, exclude } => {
                write_dot_separated_list(f, qualified)?;
                if let Some(cols) = exclude {
                    // EXCLUDE
                    if !cols.is_empty() {
                        write!(f, " EXCLUDE (")?;
                        write_comma_separated_list(f, cols)?;
                        write!(f, ")")?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl Display for SelectStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // SELECT clause
        write!(f, "SELECT ")?;
        if let Some(hints) = &self.hints {
            write!(f, "{} ", hints)?;
        }
        if self.distinct {
            write!(f, "DISTINCT ")?;
        }
        write_comma_separated_list(f, &self.select_list)?;

        // FROM clause
        if !self.from.is_empty() {
            write!(f, " FROM ")?;
            write_comma_separated_list(f, &self.from)?;
        }

        // WHERE clause
        if let Some(expr) = &self.selection {
            write!(f, " WHERE {expr}")?;
        }

        // GROUP BY clause
        if self.group_by.is_some() {
            write!(f, " GROUP BY ")?;
            match self.group_by.as_ref().unwrap() {
                GroupBy::Normal(exprs) => {
                    write_comma_separated_list(f, exprs)?;
                }
                GroupBy::All => {
                    write!(f, "ALL")?;
                }
                GroupBy::GroupingSets(sets) => {
                    write!(f, "GROUPING SETS (")?;
                    for (i, set) in sets.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "(")?;
                        write_comma_separated_list(f, set)?;
                        write!(f, ")")?;
                    }
                    write!(f, ")")?;
                }
                GroupBy::Cube(exprs) => {
                    write!(f, "CUBE (")?;
                    write_comma_separated_list(f, exprs)?;
                    write!(f, ")")?;
                }
                GroupBy::Rollup(exprs) => {
                    write!(f, "ROLLUP (")?;
                    write_comma_separated_list(f, exprs)?;
                    write!(f, ")")?;
                }
            }
        }

        // HAVING clause
        if let Some(having) = &self.having {
            write!(f, " HAVING {having}")?;
        }

        Ok(())
    }
}

impl Display for SetExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SetExpr::Select(select_stmt) => {
                write!(f, "{select_stmt}")?;
            }
            SetExpr::Query(query) => {
                write!(f, "({query})")?;
            }
            SetExpr::SetOperation(set_operation) => {
                write!(f, "{}", set_operation.left)?;
                match set_operation.op {
                    SetOperator::Union => {
                        write!(f, " UNION ")?;
                    }
                    SetOperator::Except => {
                        write!(f, " EXCEPT ")?;
                    }
                    SetOperator::Intersect => {
                        write!(f, " INTERSECT ")?;
                    }
                }
                if set_operation.all {
                    write!(f, "ALL ")?;
                }
                write!(f, "{}", set_operation.right)?;
            }
            SetExpr::Values { values, .. } => {
                write!(f, "VALUES")?;
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "(")?;
                    write_comma_separated_list(f, value)?;
                    write!(f, ")")?;
                }
            }
        }
        Ok(())
    }
}

impl Display for CTE {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} AS ", self.alias)?;
        if self.materialized {
            write!(f, "MATERIALIZED ")?;
        }
        write!(f, "({})", self.query)?;
        Ok(())
    }
}

impl Display for With {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.recursive {
            write!(f, "RECURSIVE ")?;
        }

        write_comma_separated_list(f, &self.ctes)?;
        Ok(())
    }
}

impl Display for Query {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // CTE, with clause
        if let Some(with) = &self.with {
            write!(f, "WITH {with} ")?;
        }

        // Query body
        write!(f, "{}", self.body)?;

        // ORDER BY clause
        if !self.order_by.is_empty() {
            write!(f, " ORDER BY ")?;
            write_comma_separated_list(f, &self.order_by)?;
        }

        // LIMIT clause
        if !self.limit.is_empty() {
            write!(f, " LIMIT ")?;
            write_comma_separated_list(f, &self.limit)?;
        }

        // TODO: We should validate if offset exists, limit should be empty or just one element
        if let Some(offset) = &self.offset {
            write!(f, " OFFSET {offset}")?;
        }

        Ok(())
    }
}

impl Display for TimeTravelPoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeTravelPoint::Snapshot(sid) => {
                write!(f, " (SNAPSHOT => {sid})")?;
            }
            TimeTravelPoint::Timestamp(ts) => {
                write!(f, " (TIMESTAMP => {ts})")?;
            }
        }

        Ok(())
    }
}
