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

use common_exception::Span;
use crate::meta::FileFormatOptionsAst;
use crate::meta::principal_identity::PrincipalIdentity;
use crate::meta::user_identity::UserIdentity;

use super::walk::walk_cte;
use super::walk::walk_expr;
use super::walk::walk_identifier;
use super::walk::walk_join_condition;
use super::walk::walk_query;
use super::walk::walk_select_target;
use super::walk::walk_set_expr;
use super::walk::walk_statement;
use super::walk::walk_table_reference;
use super::walk_time_travel_point;
use crate::ast::*;
use crate::visitors::walk_window_definition;

pub trait Visitor<'ast>: Sized {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        walk_expr(self, expr);
    }

    fn visit_identifier(&mut self, _ident: &'ast Identifier) {}

    fn visit_column_id(&mut self, column: &'ast ColumnID) {
        match column {
            ColumnID::Name(ident) => {
                self.visit_identifier(ident);
            }
            ColumnID::Position(pos) => {
                self.visit_column_position(pos);
            }
        }
    }

    fn visit_column_position(&mut self, _column: &'ast ColumnPosition) {}

    fn visit_database_ref(
        &mut self,
        catalog: &'ast Option<Identifier>,
        database: &'ast Identifier,
    ) {
        if let Some(catalog) = catalog {
            walk_identifier(self, catalog);
        }

        walk_identifier(self, database);
    }

    fn visit_table_ref(
        &mut self,
        catalog: &'ast Option<Identifier>,
        database: &'ast Option<Identifier>,
        table: &'ast Identifier,
    ) {
        if let Some(catalog) = catalog {
            walk_identifier(self, catalog);
        }

        if let Some(database) = database {
            walk_identifier(self, database);
        }

        walk_identifier(self, table);
    }

    fn visit_index_ref(&mut self, index: &'ast Identifier) {
        walk_identifier(self, index);
    }

    fn visit_column_ref(
        &mut self,
        _span: Span,
        database: &'ast Option<Identifier>,
        table: &'ast Option<Identifier>,
        column: &'ast ColumnID,
    ) {
        if let Some(database) = database {
            walk_identifier(self, database);
        }

        if let Some(table) = table {
            walk_identifier(self, table);
        }

        self.visit_column_id(column);
    }

    fn visit_is_null(&mut self, _span: Span, expr: &'ast Expr, _not: bool) {
        walk_expr(self, expr);
    }

    fn visit_is_distinct_from(
        &mut self,
        _span: Span,
        left: &'ast Expr,
        right: &'ast Expr,
        _not: bool,
    ) {
        walk_expr(self, left);
        walk_expr(self, right);
    }

    fn visit_in_list(&mut self, _span: Span, expr: &'ast Expr, list: &'ast [Expr], _not: bool) {
        walk_expr(self, expr);
        for expr in list {
            walk_expr(self, expr);
        }
    }

    fn visit_in_subquery(
        &mut self,
        _span: Span,
        expr: &'ast Expr,
        subquery: &'ast Query,
        _not: bool,
    ) {
        walk_expr(self, expr);
        walk_query(self, subquery);
    }

    fn visit_between(
        &mut self,
        _span: Span,
        expr: &'ast Expr,
        low: &'ast Expr,
        high: &'ast Expr,
        _not: bool,
    ) {
        walk_expr(self, expr);
        walk_expr(self, low);
        walk_expr(self, high);
    }

    fn visit_binary_op(
        &mut self,
        _span: Span,
        _op: &'ast BinaryOperator,
        left: &'ast Expr,
        right: &'ast Expr,
    ) {
        walk_expr(self, left);
        walk_expr(self, right);
    }

    fn visit_unary_op(&mut self, _span: Span, _op: &'ast UnaryOperator, expr: &'ast Expr) {
        walk_expr(self, expr);
    }

    fn visit_cast(
        &mut self,
        _span: Span,
        expr: &'ast Expr,
        _target_type: &'ast TypeName,
        _pg_style: bool,
    ) {
        walk_expr(self, expr);
    }

    fn visit_try_cast(&mut self, _span: Span, expr: &'ast Expr, _target_type: &'ast TypeName) {
        walk_expr(self, expr);
    }

    fn visit_extract(&mut self, _span: Span, _kind: &'ast IntervalKind, expr: &'ast Expr) {
        walk_expr(self, expr);
    }

    fn visit_position(&mut self, _span: Span, substr_expr: &'ast Expr, str_expr: &'ast Expr) {
        walk_expr(self, substr_expr);
        walk_expr(self, str_expr);
    }

    fn visit_substring(
        &mut self,
        _span: Span,
        expr: &'ast Expr,
        substring_from: &'ast Expr,
        substring_for: &'ast Option<Box<Expr>>,
    ) {
        walk_expr(self, expr);
        walk_expr(self, substring_from);
        if let Some(substring_for) = substring_for {
            walk_expr(self, substring_for);
        }
    }

    fn visit_trim(
        &mut self,
        _span: Span,
        expr: &'ast Expr,
        _trim_where: &'ast Option<(TrimWhere, Box<Expr>)>,
    ) {
        walk_expr(self, expr);
    }

    fn visit_literal(&mut self, _span: Span, _lit: &'ast Literal) {}

    fn visit_count_all(&mut self, _span: Span, window: &'ast Option<Window>) {
        if let Some(window) = window {
            self.visit_window(window);
        }
    }

    fn visit_tuple(&mut self, _span: Span, elements: &'ast [Expr]) {
        for element in elements {
            walk_expr(self, element);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_function_call(
        &mut self,
        _span: Span,
        _distinct: bool,
        _name: &'ast Identifier,
        args: &'ast [Expr],
        _params: &'ast [Literal],
        over: &'ast Option<Window>,
        lambda: &'ast Option<Lambda>,
    ) {
        for arg in args {
            walk_expr(self, arg);
        }

        if let Some(over) = over {
            self.visit_window(over);
        }
        if let Some(lambda) = lambda {
            walk_expr(self, &lambda.expr)
        }
    }

    fn visit_window(&mut self, window: &'ast Window) {
        match window {
            Window::WindowReference(reference) => {
                self.visit_identifier(&reference.window_name);
            }
            Window::WindowSpec(spec) => {
                spec.partition_by
                    .iter()
                    .for_each(|expr| walk_expr(self, expr));
                spec.order_by
                    .iter()
                    .for_each(|expr| walk_expr(self, &expr.expr));

                if let Some(frame) = &spec.window_frame {
                    self.visit_frame_bound(&frame.start_bound);
                    self.visit_frame_bound(&frame.end_bound);
                }
            }
        }
    }

    fn visit_frame_bound(&mut self, bound: &'ast WindowFrameBound) {
        match bound {
            WindowFrameBound::Preceding(Some(expr)) => walk_expr(self, expr.as_ref()),
            WindowFrameBound::Following(Some(expr)) => walk_expr(self, expr.as_ref()),
            _ => {}
        }
    }

    fn visit_case_when(
        &mut self,
        _span: Span,
        operand: &'ast Option<Box<Expr>>,
        conditions: &'ast [Expr],
        results: &'ast [Expr],
        else_result: &'ast Option<Box<Expr>>,
    ) {
        if let Some(operand) = operand {
            walk_expr(self, operand);
        }
        for condition in conditions {
            walk_expr(self, condition);
        }
        for result in results {
            walk_expr(self, result);
        }
        if let Some(else_result) = else_result {
            walk_expr(self, else_result);
        }
    }

    fn visit_exists(&mut self, _span: Span, _not: bool, subquery: &'ast Query) {
        walk_query(self, subquery);
    }

    fn visit_subquery(
        &mut self,
        _span: Span,
        _modifier: &'ast Option<SubqueryModifier>,
        subquery: &'ast Query,
    ) {
        walk_query(self, subquery);
    }

    fn visit_map_access(&mut self, _span: Span, expr: &'ast Expr, _accessor: &'ast MapAccessor) {
        walk_expr(self, expr);
    }

    fn visit_array(&mut self, _span: Span, exprs: &'ast [Expr]) {
        for expr in exprs {
            walk_expr(self, expr);
        }
    }

    fn visit_map(&mut self, _span: Span, kvs: &'ast [(Literal, Literal)]) {
        for (key_expr, val_expr) in kvs {
            self.visit_literal(_span, key_expr);
            self.visit_literal(_span, val_expr);
        }
    }

    fn visit_interval(&mut self, _span: Span, expr: &'ast Expr, _unit: &'ast IntervalKind) {
        walk_expr(self, expr);
    }

    fn visit_date_add(
        &mut self,
        _span: Span,
        _unit: &'ast IntervalKind,
        interval: &'ast Expr,
        date: &'ast Expr,
    ) {
        walk_expr(self, date);
        walk_expr(self, interval);
    }

    fn visit_date_sub(
        &mut self,
        _span: Span,
        _unit: &'ast IntervalKind,
        interval: &'ast Expr,
        date: &'ast Expr,
    ) {
        walk_expr(self, date);
        walk_expr(self, interval);
    }

    fn visit_date_trunc(&mut self, _span: Span, _unit: &'ast IntervalKind, date: &'ast Expr) {
        walk_expr(self, date);
    }

    fn visit_statement(&mut self, statement: &'ast Statement) {
        walk_statement(self, statement);
    }

    fn visit_query(&mut self, query: &'ast Query) {
        walk_query(self, query);
    }

    fn visit_explain(&mut self, _kind: &'ast ExplainKind, _query: &'ast Statement) {}

    fn visit_copy(&mut self, _copy: &'ast CopyStmt) {}

    fn visit_copy_unit(&mut self, _copy_unit: &'ast CopyUnit) {}

    fn visit_call(&mut self, _call: &'ast CallStmt) {}

    fn visit_show_settings(&mut self, _like: &'ast Option<String>) {}

    fn visit_unset_variable(&mut self, _stmt: &'ast UnSetStmt) {}

    fn visit_show_process_list(&mut self) {}

    fn visit_show_metrics(&mut self) {}

    fn visit_show_engines(&mut self) {}

    fn visit_show_functions(&mut self, _limit: &'ast Option<ShowLimit>) {}

    fn visit_show_table_functions(&mut self, _limit: &'ast Option<ShowLimit>) {}

    fn visit_show_limit(&mut self, _limit: &'ast ShowLimit) {}

    fn visit_show_indexes(&mut self) {}

    fn visit_kill(&mut self, _kill_target: &'ast KillTarget, _object_id: &'ast str) {}

    fn visit_set_variable(
        &mut self,
        _is_global: bool,
        _variable: &'ast Identifier,
        _value: &'ast Expr,
    ) {
    }

    fn visit_set_role(&mut self, _is_default: bool, _role_name: &'ast str) {}

    fn visit_insert(&mut self, _insert: &'ast InsertStmt) {}
    fn visit_replace(&mut self, _replace: &'ast ReplaceStmt) {}
    fn visit_merge_into(&mut self, _merge_into: &'ast MergeIntoStmt) {}
    fn visit_insert_source(&mut self, _insert_source: &'ast InsertSource) {}

    fn visit_delete(
        &mut self,
        _table_reference: &'ast TableReference,
        _selection: &'ast Option<Expr>,
    ) {
    }

    fn visit_update(&mut self, _update: &'ast UpdateStmt) {}

    fn visit_show_catalogs(&mut self, _stmt: &'ast ShowCatalogsStmt) {}

    fn visit_show_create_catalog(&mut self, _stmt: &'ast ShowCreateCatalogStmt) {}

    fn visit_create_catalog(&mut self, _stmt: &'ast CreateCatalogStmt) {}

    fn visit_drop_catalog(&mut self, _stmt: &'ast DropCatalogStmt) {}

    fn visit_show_databases(&mut self, _stmt: &'ast ShowDatabasesStmt) {}

    fn visit_show_create_databases(&mut self, _stmt: &'ast ShowCreateDatabaseStmt) {}

    fn visit_create_database(&mut self, _stmt: &'ast CreateDatabaseStmt) {}

    fn visit_drop_database(&mut self, _stmt: &'ast DropDatabaseStmt) {}

    fn visit_undrop_database(&mut self, _stmt: &'ast UndropDatabaseStmt) {}

    fn visit_alter_database(&mut self, _stmt: &'ast AlterDatabaseStmt) {}

    fn visit_use_database(&mut self, _database: &'ast Identifier) {}

    fn visit_show_tables(&mut self, _stmt: &'ast ShowTablesStmt) {}

    fn visit_show_columns(&mut self, _stmt: &'ast ShowColumnsStmt) {}

    fn visit_show_create_table(&mut self, _stmt: &'ast ShowCreateTableStmt) {}

    fn visit_describe_table(&mut self, _stmt: &'ast DescribeTableStmt) {}

    fn visit_show_tables_status(&mut self, _stmt: &'ast ShowTablesStatusStmt) {}

    fn visit_show_drop_tables(&mut self, _stmt: &'ast ShowDropTablesStmt) {}

    fn visit_create_table(&mut self, _stmt: &'ast CreateTableStmt) {}

    fn visit_create_table_source(&mut self, _source: &'ast CreateTableSource) {}

    fn visit_column_definition(&mut self, _column_definition: &'ast ColumnDefinition) {}

    fn visit_drop_table(&mut self, _stmt: &'ast DropTableStmt) {}

    fn visit_undrop_table(&mut self, _stmt: &'ast UndropTableStmt) {}

    fn visit_alter_table(&mut self, _stmt: &'ast AlterTableStmt) {}

    fn visit_rename_table(&mut self, _stmt: &'ast RenameTableStmt) {}

    fn visit_truncate_table(&mut self, _stmt: &'ast TruncateTableStmt) {}

    fn visit_optimize_table(&mut self, _stmt: &'ast OptimizeTableStmt) {}

    fn visit_vacuum_table(&mut self, _stmt: &'ast VacuumTableStmt) {}

    fn visit_vacuum_drop_table(&mut self, _stmt: &'ast VacuumDropTableStmt) {}

    fn visit_analyze_table(&mut self, _stmt: &'ast AnalyzeTableStmt) {}

    fn visit_exists_table(&mut self, _stmt: &'ast ExistsTableStmt) {}

    fn visit_create_view(&mut self, _stmt: &'ast CreateViewStmt) {}

    fn visit_alter_view(&mut self, _stmt: &'ast AlterViewStmt) {}

    fn visit_drop_view(&mut self, _stmt: &'ast DropViewStmt) {}

    fn visit_create_index(&mut self, _stmt: &'ast CreateIndexStmt) {}

    fn visit_drop_index(&mut self, _stmt: &'ast DropIndexStmt) {}
    fn visit_refresh_index(&mut self, _stmt: &'ast RefreshIndexStmt) {}

    fn visit_create_virtual_column(&mut self, _stmt: &'ast CreateVirtualColumnStmt) {}

    fn visit_alter_virtual_column(&mut self, _stmt: &'ast AlterVirtualColumnStmt) {}

    fn visit_drop_virtual_column(&mut self, _stmt: &'ast DropVirtualColumnStmt) {}

    fn visit_refresh_virtual_column(&mut self, _stmt: &'ast RefreshVirtualColumnStmt) {}

    fn visit_show_users(&mut self) {}

    fn visit_create_user(&mut self, _stmt: &'ast CreateUserStmt) {}

    fn visit_alter_user(&mut self, _stmt: &'ast AlterUserStmt) {}

    fn visit_drop_user(&mut self, _if_exists: bool, _user: &'ast UserIdentity) {}

    fn visit_show_roles(&mut self) {}

    fn visit_create_role(&mut self, _if_not_exists: bool, _role_name: &'ast str) {}

    fn visit_drop_role(&mut self, _if_exists: bool, _role_name: &'ast str) {}

    fn visit_grant(&mut self, _grant: &'ast GrantStmt) {}

    fn visit_show_grant(&mut self, _principal: &'ast Option<PrincipalIdentity>) {}

    fn visit_revoke(&mut self, _revoke: &'ast RevokeStmt) {}

    fn visit_create_udf(&mut self, _stmt: &'ast CreateUDFStmt) {}

    fn visit_drop_udf(&mut self, _if_exists: bool, _udf_name: &'ast Identifier) {}

    fn visit_alter_udf(&mut self, _stmt: &'ast AlterUDFStmt) {}

    fn visit_create_stage(&mut self, _stmt: &'ast CreateStageStmt) {}

    fn visit_show_stages(&mut self) {}

    fn visit_drop_stage(&mut self, _if_exists: bool, _stage_name: &'ast str) {}

    fn visit_describe_stage(&mut self, _stage_name: &'ast str) {}

    fn visit_remove_stage(&mut self, _location: &'ast str, _pattern: &'ast str) {}

    fn visit_list_stage(&mut self, _location: &'ast str, _pattern: &'ast str) {}

    fn visit_create_file_format(
        &mut self,
        _if_not_exists: bool,
        _name: &'ast str,
        _file_format_options: &'ast FileFormatOptionsAst,
    ) {
    }

    fn visit_drop_file_format(&mut self, _if_exists: bool, _name: &'ast str) {}

    fn visit_show_file_formats(&mut self) {}

    fn visit_presign(&mut self, _presign: &'ast PresignStmt) {}

    fn visit_create_share_endpoint(&mut self, _stmt: &'ast CreateShareEndpointStmt) {}

    fn visit_show_share_endpoint(&mut self, _stmt: &'ast ShowShareEndpointStmt) {}

    fn visit_drop_share_endpoint(&mut self, _stmt: &'ast DropShareEndpointStmt) {}

    fn visit_create_share(&mut self, _stmt: &'ast CreateShareStmt) {}

    fn visit_drop_share(&mut self, _stmt: &'ast DropShareStmt) {}

    fn visit_grant_share_object(&mut self, _stmt: &'ast GrantShareObjectStmt) {}

    fn visit_revoke_share_object(&mut self, _stmt: &'ast RevokeShareObjectStmt) {}

    fn visit_alter_share_tenants(&mut self, _stmt: &'ast AlterShareTenantsStmt) {}

    fn visit_desc_share(&mut self, _stmt: &'ast DescShareStmt) {}

    fn visit_show_shares(&mut self, _stmt: &'ast ShowSharesStmt) {}

    fn visit_show_object_grant_privileges(&mut self, _stmt: &'ast ShowObjectGrantPrivilegesStmt) {}

    fn visit_show_grants_of_share(&mut self, _stmt: &'ast ShowGrantsOfShareStmt) {}

    fn visit_create_data_mask_policy(&mut self, _stmt: &'ast CreateDatamaskPolicyStmt) {}

    fn visit_drop_data_mask_policy(&mut self, _stmt: &'ast DropDatamaskPolicyStmt) {}

    fn visit_desc_data_mask_policy(&mut self, _stmt: &'ast DescDatamaskPolicyStmt) {}

    fn visit_create_network_policy(&mut self, _stmt: &'ast CreateNetworkPolicyStmt) {}

    fn visit_alter_network_policy(&mut self, _stmt: &'ast AlterNetworkPolicyStmt) {}

    fn visit_drop_network_policy(&mut self, _stmt: &'ast DropNetworkPolicyStmt) {}

    fn visit_desc_network_policy(&mut self, _stmt: &'ast DescNetworkPolicyStmt) {}

    fn visit_show_network_policies(&mut self) {}

    fn visit_with(&mut self, with: &'ast With) {
        let With { ctes, .. } = with;
        for cte in ctes.iter() {
            walk_cte(self, cte);
        }
    }

    fn visit_set_expr(&mut self, expr: &'ast SetExpr) {
        walk_set_expr(self, expr);
    }

    fn visit_set_operation(&mut self, op: &'ast SetOperation) {
        let SetOperation { left, right, .. } = op;

        walk_set_expr(self, left);
        walk_set_expr(self, right);
    }

    fn visit_order_by(&mut self, order_by: &'ast OrderByExpr) {
        let OrderByExpr { expr, .. } = order_by;
        walk_expr(self, expr);
    }

    fn visit_select_stmt(&mut self, stmt: &'ast SelectStmt) {
        let SelectStmt {
            select_list,
            from,
            selection,
            group_by,
            having,
            ..
        } = stmt;

        for target in select_list.iter() {
            walk_select_target(self, target);
        }

        for table_ref in from.iter() {
            walk_table_reference(self, table_ref);
        }

        if let Some(selection) = selection {
            walk_expr(self, selection);
        }

        match group_by {
            Some(GroupBy::Normal(exprs)) => {
                for expr in exprs {
                    walk_expr(self, expr);
                }
            }
            Some(GroupBy::GroupingSets(sets)) => {
                for set in sets {
                    for expr in set {
                        walk_expr(self, expr);
                    }
                }
            }
            _ => {}
        }

        if let Some(having) = having {
            walk_expr(self, having);
        }
    }

    fn visit_select_target(&mut self, target: &'ast SelectTarget) {
        walk_select_target(self, target);
    }

    fn visit_table_reference(&mut self, table: &'ast TableReference) {
        walk_table_reference(self, table);
    }

    fn visit_time_travel_point(&mut self, time: &'ast TimeTravelPoint) {
        walk_time_travel_point(self, time);
    }

    fn visit_join(&mut self, join: &'ast Join) {
        let Join {
            left,
            right,
            condition,
            ..
        } = join;

        walk_table_reference(self, left);
        walk_table_reference(self, right);

        walk_join_condition(self, condition);
    }
    fn visit_window_definition(&mut self, window_definition: &'ast WindowDefinition) {
        walk_window_definition(self, window_definition);
    }
}
