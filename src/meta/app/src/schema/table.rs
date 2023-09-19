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

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::ops::Deref;
use std::sync::Arc;

use chrono::DateTime;
use chrono::Utc;
use common_exception::Result;
use common_meta_types::MatchSeq;
use common_meta_types::MetaId;
use maplit::hashmap;

use crate::schema::database::DatabaseNameIdent;
use crate::schema::Ownership;
use crate::share::ShareNameIdent;
use crate::share::ShareSpec;
use crate::storage::StorageParams;

/// Globally unique identifier of a version of TableMeta.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct TableIdent {
    /// Globally unique id to identify a table.
    pub table_id: u64,

    /// seq AKA version of this table snapshot.
    ///
    /// Any change to a table causes the seq to increment, e.g. insert or delete rows, update schema etc.
    /// But renaming a table should not affect the seq, since the table itself does not change.
    /// The tuple (table_id, seq) identifies a unique and consistent table snapshot.
    ///
    /// A seq is not guaranteed to be consecutive.
    pub seq: u64,
}

impl TableIdent {
    pub fn new(table_id: u64, seq: u64) -> Self {
        TableIdent { table_id, seq }
    }
}

impl Display for TableIdent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "table_id:{}, ver:{}", self.table_id, self.seq)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableNameIdent {
    pub tenant: String,
    pub db_name: String,
    pub table_name: String,
}

impl TableNameIdent {
    pub fn new(
        tenant: impl Into<String>,
        db_name: impl Into<String>,
        table_name: impl Into<String>,
    ) -> TableNameIdent {
        TableNameIdent {
            tenant: tenant.into(),
            db_name: db_name.into(),
            table_name: table_name.into(),
        }
    }

    pub fn table_name(&self) -> String {
        self.table_name.clone()
    }

    pub fn db_name_ident(&self) -> DatabaseNameIdent {
        DatabaseNameIdent {
            tenant: self.tenant.clone(),
            db_name: self.db_name.clone(),
        }
    }
}

impl Display for TableNameIdent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}'.'{}'.'{}'",
            self.tenant, self.db_name, self.table_name
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct DBIdTableName {
    pub db_id: u64,
    pub table_name: String,
}

impl Display for DBIdTableName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.'{}'", self.db_id, self.table_name)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableId {
    pub table_id: u64,
}

impl Display for TableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "TableId{{{}}}", self.table_id)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableIdListKey {
    pub db_id: u64,
    pub table_name: String,
}

impl Display for TableIdListKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.'{}'", self.db_id, self.table_name)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub enum DatabaseType {
    #[default]
    NormalDB,
    ShareDB(ShareNameIdent),
}

impl Display for DatabaseType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseType::NormalDB => {
                write!(f, "normal database")
            }
            DatabaseType::ShareDB(share_ident) => {
                write!(
                    f,
                    "share database: {}-{}",
                    share_ident.tenant, share_ident.share_name
                )
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableStatistics {
    /// Number of rows
    pub number_of_rows: u64,
    // Size of data in bytes
    pub data_bytes: u64,
    /// Size of data compressed in bytes
    pub compressed_data_bytes: u64,
    /// Size of index data in bytes
    pub index_data_bytes: u64,

    /// number of segments
    pub number_of_segments: Option<u64>,

    /// number of blocks
    pub number_of_blocks: Option<u64>,
}

/// Save table name id list history.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TableIdList {
    pub id_list: Vec<u64>,
}

impl TableIdList {
    pub fn new() -> TableIdList {
        TableIdList::default()
    }

    pub fn len(&self) -> usize {
        self.id_list.len()
    }

    pub fn id_list(&self) -> &Vec<u64> {
        &self.id_list
    }

    pub fn append(&mut self, table_id: u64) {
        self.id_list.push(table_id);
    }

    pub fn is_empty(&self) -> bool {
        self.id_list.is_empty()
    }

    pub fn pop(&mut self) -> Option<u64> {
        self.id_list.pop()
    }

    pub fn last(&mut self) -> Option<&u64> {
        self.id_list.last()
    }
}

impl Display for TableIdList {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "DB.Table id list: {:?}", self.id_list)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CreateTableReply {
    pub table_id: u64,
    pub new_table: bool,
}

/// Drop table by id.
///
/// Dropping a table requires just `table_id`, but when dropping a table, it also needs to update
/// the count of tables belonging to a tenant, which require tenant information.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropTableByIdReq {
    pub if_exists: bool,

    pub tenant: String,

    pub tb_id: MetaId,
}

impl DropTableByIdReq {
    pub fn tb_id(&self) -> MetaId {
        self.tb_id
    }
}

impl Display for DropTableByIdReq {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "drop_table_by_id(if_exists={}):{}",
            self.if_exists,
            self.tb_id(),
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UndropTableReq {
    pub name_ident: TableNameIdent,
}

impl UndropTableReq {
    pub fn tenant(&self) -> &str {
        &self.name_ident.tenant
    }
    pub fn db_name(&self) -> &str {
        &self.name_ident.db_name
    }
    pub fn table_name(&self) -> &str {
        &self.name_ident.table_name
    }
}

impl Display for UndropTableReq {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "undrop_table:{}/{}-{}",
            self.tenant(),
            self.db_name(),
            self.table_name()
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UndropTableReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RenameTableReq {
    pub if_exists: bool,
    pub name_ident: TableNameIdent,
    pub new_db_name: String,
    pub new_table_name: String,
}

impl RenameTableReq {
    pub fn tenant(&self) -> &str {
        &self.name_ident.tenant
    }
    pub fn db_name(&self) -> &str {
        &self.name_ident.db_name
    }
    pub fn table_name(&self) -> &str {
        &self.name_ident.table_name
    }
}

impl Display for RenameTableReq {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rename_table:{}/{}-{}=>{}-{}",
            self.tenant(),
            self.db_name(),
            self.table_name(),
            self.new_db_name,
            self.new_table_name
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RenameTableReply {
    pub table_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpsertTableOptionReq {
    pub table_id: u64,
    pub seq: MatchSeq,

    /// Add or remove options
    ///
    /// Some(String): add or update an option.
    /// None: delete an option.
    pub options: HashMap<String, Option<String>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SetTableColumnMaskPolicyAction {
    // new mask name, old mask name(if any)
    Set(String, Option<String>),
    // prev mask name
    Unset(String),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SetTableColumnMaskPolicyReq {
    pub tenant: String,
    pub table_id: u64,
    pub seq: MatchSeq,
    pub column: String,
    pub action: SetTableColumnMaskPolicyAction,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTableReq {
    pub inner: TableNameIdent,
}

impl Deref for GetTableReq {
    type Target = TableNameIdent;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<(&str, &str, &str)> for GetTableReq {
    fn from(db_table: (&str, &str, &str)) -> Self {
        Self::new(db_table.0, db_table.1, db_table.2)
    }
}

impl GetTableReq {
    pub fn new(
        tenant: impl Into<String>,
        db_name: impl Into<String>,
        table_name: impl Into<String>,
    ) -> GetTableReq {
        GetTableReq {
            inner: TableNameIdent::new(tenant, db_name, table_name),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ListTableReq {
    pub inner: DatabaseNameIdent,
}

impl Deref for ListTableReq {
    type Target = DatabaseNameIdent;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ListTableReq {
    pub fn new(tenant: impl Into<String>, db_name: impl Into<String>) -> ListTableReq {
        ListTableReq {
            inner: DatabaseNameIdent {
                tenant: tenant.into(),
                db_name: db_name.into(),
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TableInfoFilter {
    // if datatime is some, filter only dropped tables which drop time before that,
    // else filter all dropped tables
    Dropped(Option<DateTime<Utc>>),
    // filter all dropped tables, including all tables in dropped database and dropped tables in exist dbs,
    // in this case, `ListTableReq`.db_name will be ignored
    // return Tables in two cases:
    //  1) if database drop before date time, then all table in this db will be return;
    //  2) else, return all the tables drop before data time.
    AllDroppedTables(Option<DateTime<Utc>>),
    // return all tables, ignore drop on time.
    All,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ListDroppedTableReq {
    pub inner: DatabaseNameIdent,
    pub filter: TableInfoFilter,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum DroppedId {
    // db id, db name
    Db(u64, String),
    // db id, table id, table name
    Table(u64, u64, String),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GcDroppedTableReq {
    pub tenant: String,
    pub drop_ids: Vec<DroppedId>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GcDroppedTableResp {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct CountTablesKey {
    pub tenant: String,
}

impl Display for CountTablesKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'", self.tenant)
    }
}

/// count tables for a tenant
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CountTablesReq {
    pub tenant: String,
}

#[derive(Debug)]
pub struct CountTablesReply {
    pub count: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct TableIdToName {
    pub table_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableCopiedFileNameIdent {
    pub table_id: u64,
    pub file: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq, Default)]
pub struct TableCopiedFileInfo {
    pub etag: Option<String>,
    pub content_length: u64,
    pub last_modified: Option<DateTime<Utc>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTableCopiedFileReq {
    pub table_id: u64,
    pub files: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetTableCopiedFileReply {
    pub file_info: BTreeMap<String, TableCopiedFileInfo>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpsertTableCopiedFileReq {
    pub file_info: BTreeMap<String, TableCopiedFileInfo>,
    pub expire_at: Option<u64>,
    pub fail_if_duplicated: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpsertTableCopiedFileReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TruncateTableReq {
    pub table_id: u64,
    /// Specify the max number copied file to delete in every sub-transaction.
    ///
    /// By default it use `DEFAULT_MGET_SIZE=256`
    pub batch_size: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TruncateTableReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TableCopiedFileLockKey {
    pub table_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EmptyProto {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TableLockKey {
    pub table_id: u64,
    pub revision: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ListTableLockRevReq {
    pub table_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateTableLockRevReq {
    pub table_id: u64,
    pub expire_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateTableLockRevReply {
    pub revision: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExtendTableLockRevReq {
    pub table_id: u64,
    pub expire_at: u64,
    pub revision: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeleteTableLockRevReq {
    pub table_id: u64,
    pub revision: u64,
}