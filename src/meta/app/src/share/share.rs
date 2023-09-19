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
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use chrono::DateTime;
use chrono::Utc;
use enumflags2::bitflags;
use enumflags2::BitFlags;

use crate::app_error::AppError;
use crate::app_error::WrongShareObject;
use crate::schema::DatabaseMeta;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareNameIdent {
    pub tenant: String,
    pub share_name: String,
}

impl Display for ShareNameIdent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'/'{}'", self.tenant, self.share_name)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareAccountNameIdent {
    pub account: String,
    pub share_id: u64,
}

impl Display for ShareAccountNameIdent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'/'{}'", self.account, self.share_id)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareEndpointIdent {
    pub tenant: String,
    pub endpoint: String,
}

impl Display for ShareEndpointIdent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'/'{}'", self.tenant, self.endpoint)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShowSharesReq {
    pub tenant: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShareAccountReply {
    pub share_name: ShareNameIdent,
    pub database_name: Option<String>,
    // for outbound share account, it is the time share has been created.
    // for inbound share account, it is the time accounts has been added to the share.
    pub create_on: DateTime<Utc>,
    // if is inbound share, then accounts is None
    pub accounts: Option<Vec<String>>,
    pub comment: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShowSharesReply {
    // sharing to other accounts(outbound shares)
    pub outbound_accounts: Vec<ShareAccountReply>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateShareReq {
    pub if_not_exists: bool,
    pub share_name: ShareNameIdent,
    pub comment: Option<String>,
    pub create_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateShareReply {
    pub share_id: u64,

    pub spec_vec: Option<Vec<ShareSpec>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropShareReq {
    pub share_name: ShareNameIdent,
    pub if_exists: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropShareReply {
    pub share_id: Option<u64>,
    pub spec_vec: Option<Vec<ShareSpec>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddShareAccountsReq {
    pub share_name: ShareNameIdent,
    pub if_exists: bool,
    pub accounts: Vec<String>,
    pub share_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AddShareAccountsReply {
    pub share_id: Option<u64>,
    pub spec_vec: Option<Vec<ShareSpec>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveShareAccountsReq {
    pub share_name: ShareNameIdent,
    pub if_exists: bool,
    pub accounts: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveShareAccountsReply {
    pub share_id: Option<u64>,
    pub spec_vec: Option<Vec<ShareSpec>>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShowShareOfReq {
    pub share_name: ShareNameIdent,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShowShareOfReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ShareGrantObjectName {
    // database name
    Database(String),
    // database name, table name
    Table(String, String),
}

impl Display for ShareGrantObjectName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareGrantObjectName::Database(db) => {
                write!(f, "DATABASE {}", db)
            }
            ShareGrantObjectName::Table(db, table) => {
                write!(f, "TABLE {}.{}", db, table)
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GrantShareObjectReq {
    pub share_name: ShareNameIdent,
    pub object: ShareGrantObjectName,
    pub grant_on: DateTime<Utc>,
    pub privilege: ShareGrantObjectPrivilege,
}


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RevokeShareObjectReq {
    pub share_name: ShareNameIdent,
    pub object: ShareGrantObjectName,
    pub privilege: ShareGrantObjectPrivilege,
    pub update_on: DateTime<Utc>,
}


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareGrantObjectReq {
    pub share_name: ShareNameIdent,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShareGrantReplyObject {
    pub object: ShareGrantObjectName,
    pub privileges: BitFlags<ShareGrantObjectPrivilege>,
    pub grant_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareGrantObjectReply {
    pub share_name: ShareNameIdent,
    pub objects: Vec<ShareGrantReplyObject>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareGrantTenantsReq {
    pub share_name: ShareNameIdent,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareGrantTenants {
    pub account: String,
    pub grant_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareGrantTenantsReply {
    pub accounts: Vec<GetShareGrantTenants>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetObjectGrantPrivilegesReq {
    pub tenant: String,
    pub object: ShareGrantObjectName,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ObjectGrantPrivilege {
    pub share_name: String,
    pub privileges: BitFlags<ShareGrantObjectPrivilege>,
    pub grant_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetObjectGrantPrivilegesReply {
    pub privileges: Vec<ObjectGrantPrivilege>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateShareEndpointReq {
    pub if_not_exists: bool,
    pub endpoint: ShareEndpointIdent,
    pub url: String,
    pub tenant: String,
    pub args: BTreeMap<String, String>,
    pub comment: Option<String>,
    pub create_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateShareEndpointReply {
    pub share_endpoint_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpsertShareEndpointReq {
    pub endpoint: ShareEndpointIdent,
    pub url: String,
    pub tenant: String,
    pub args: BTreeMap<String, String>,
    pub create_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpsertShareEndpointReply {
    pub share_endpoint_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareEndpointReq {
    pub tenant: String,
    // If `endpoint` is not None, return the specified endpoint,
    // else return all share endpoints meta of tenant
    pub endpoint: Option<String>,

    // If `to_tenant` is not None, return the specified endpoint to the tenant,
    pub to_tenant: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetShareEndpointReply {
    pub share_endpoint_meta_vec: Vec<(ShareEndpointIdent, ShareEndpointMeta)>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropShareEndpointReq {
    pub if_exists: bool,
    pub endpoint: ShareEndpointIdent,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropShareEndpointReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct ShareEndpointMeta {
    pub url: String,
    pub tenant: String,
    pub args: BTreeMap<String, String>,
    pub comment: Option<String>,
    pub create_on: DateTime<Utc>,
}

impl ShareEndpointMeta {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(req: &CreateShareEndpointReq) -> Self {
        Self {
            url: req.url.clone(),
            tenant: req.tenant.clone(),
            args: req.args.clone(),
            comment: req.comment.clone(),
            create_on: req.create_on,
        }
    }

    pub fn if_need_to_upsert(&self, req: &UpsertShareEndpointReq) -> bool {
        // upsert only when these fields not equal
        self.url != req.url || self.args != req.args || self.tenant != req.tenant
    }

    pub fn upsert(&self, req: &UpsertShareEndpointReq) -> Self {
        let mut meta = self.clone();

        meta.url = req.url.clone();
        meta.args = req.args.clone();
        meta.tenant = req.tenant.clone();
        meta.create_on = req.create_on;

        meta
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShareAccountMeta {
    pub account: String,
    pub share_id: u64,
    pub share_on: DateTime<Utc>,
    pub accept_on: Option<DateTime<Utc>>,
}

impl ShareAccountMeta {
    pub fn new(account: String, share_id: u64, share_on: DateTime<Utc>) -> Self {
        Self {
            account,
            share_id,
            share_on,
            accept_on: None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareId {
    pub share_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareIdToName {
    pub share_id: u64,
}

impl Display for ShareIdToName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.share_id)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareEndpointId {
    pub share_endpoint_id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareEndpointIdToName {
    pub share_endpoint_id: u64,
}

impl Display for ShareEndpointIdToName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.share_endpoint_id)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ShareGrantObject {
    Database(u64),
    Table(u64),
}

impl Display for ShareGrantObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareGrantObject::Database(db_id) => {
                write!(f, "db/{}", *db_id)
            }
            ShareGrantObject::Table(table_id) => {
                write!(f, "table/{}", *table_id)
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ObjectSharedByShareIds {
    // save share ids which shares this object
    pub share_ids: BTreeSet<u64>,
}

impl Default for ObjectSharedByShareIds {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectSharedByShareIds {
    pub fn new() -> ObjectSharedByShareIds {
        ObjectSharedByShareIds {
            share_ids: BTreeSet::new(),
        }
    }

    pub fn add(&mut self, share_id: u64) {
        self.share_ids.insert(share_id);
    }

    pub fn remove(&mut self, share_id: u64) {
        self.share_ids.remove(&share_id);
    }
}

// see: https://docs.snowflake.com/en/sql-reference/sql/revoke-privilege-share.html
#[bitflags]
#[repr(u64)]
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    num_derive::FromPrimitive,
)]
pub enum ShareGrantObjectPrivilege {
    // For DATABASE or SCHEMA
    Usage = 1 << 0,
    // For DATABASE
    ReferenceUsage = 1 << 1,
    // For TABLE or VIEW
    Select = 1 << 2,
}

impl Display for ShareGrantObjectPrivilege {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            ShareGrantObjectPrivilege::Usage => write!(f, "USAGE"),
            ShareGrantObjectPrivilege::ReferenceUsage => write!(f, "REFERENCE_USAGE"),
            ShareGrantObjectPrivilege::Select => write!(f, "SELECT"),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ShareGrantEntry {
    pub object: ShareGrantObject,
    pub privileges: BitFlags<ShareGrantObjectPrivilege>,
    pub grant_on: DateTime<Utc>,
    pub update_on: Option<DateTime<Utc>>,
}

impl ShareGrantEntry {
    pub fn new(
        object: ShareGrantObject,
        privileges: ShareGrantObjectPrivilege,
        grant_on: DateTime<Utc>,
    ) -> Self {
        Self {
            object,
            privileges: BitFlags::from(privileges),
            grant_on,
            update_on: None,
        }
    }

    pub fn grant_privileges(
        &mut self,
        privileges: ShareGrantObjectPrivilege,
        grant_on: DateTime<Utc>,
    ) {
        self.update_on = Some(grant_on);
        self.privileges = BitFlags::from(privileges);
    }

    // return true if all privileges are empty.
    pub fn revoke_privileges(
        &mut self,
        privileges: ShareGrantObjectPrivilege,
        update_on: DateTime<Utc>,
    ) -> bool {
        self.update_on = Some(update_on);
        self.privileges.remove(BitFlags::from(privileges));
        self.privileges.is_empty()
    }

    pub fn object(&self) -> &ShareGrantObject {
        &self.object
    }

    pub fn privileges(&self) -> &BitFlags<ShareGrantObjectPrivilege> {
        &self.privileges
    }

    pub fn has_granted_privileges(&self, privileges: ShareGrantObjectPrivilege) -> bool {
        self.privileges.contains(privileges)
    }
}

impl Display for ShareGrantEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.object)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct ShareMeta {
    pub database: Option<ShareGrantEntry>,
    pub entries: BTreeMap<String, ShareGrantEntry>,

    // save accounts which has been granted access to this share.
    pub accounts: BTreeSet<String>,
    pub comment: Option<String>,
    pub share_on: DateTime<Utc>,
    pub update_on: Option<DateTime<Utc>>,

    // save db ids which created from this share
    pub share_from_db_ids: BTreeSet<u64>,
}

impl ShareMeta {
    pub fn new(share_on: DateTime<Utc>, comment: Option<String>) -> Self {
        ShareMeta {
            share_on,
            comment,
            ..Default::default()
        }
    }

    pub fn get_accounts(&self) -> Vec<String> {
        Vec::<String>::from_iter(self.accounts.clone().into_iter())
    }

    pub fn has_account(&self, account: &String) -> bool {
        self.accounts.contains(account)
    }

    pub fn add_account(&mut self, account: String) {
        self.accounts.insert(account);
    }

    pub fn del_account(&mut self, account: &String) {
        self.accounts.remove(account);
    }

    pub fn has_share_from_db_id(&self, db_id: u64) -> bool {
        self.share_from_db_ids.contains(&db_id)
    }

    pub fn add_share_from_db_id(&mut self, db_id: u64) {
        self.share_from_db_ids.insert(db_id);
    }

    pub fn remove_share_from_db_id(&mut self, db_id: u64) {
        self.share_from_db_ids.remove(&db_id);
    }

    pub fn get_grant_entry(&self, object: ShareGrantObject) -> Option<ShareGrantEntry> {
        let database = self.database.as_ref()?;
        if database.object == object {
            return Some(database.clone());
        }

        match object {
            ShareGrantObject::Database(_db_id) => None,
            ShareGrantObject::Table(_table_id) => self.entries.get(&object.to_string()).cloned(),
        }
    }

    pub fn grant_object_privileges(
        &mut self,
        object: ShareGrantObject,
        privileges: ShareGrantObjectPrivilege,
        grant_on: DateTime<Utc>,
    ) {
        let key = object.to_string();

        match object {
            ShareGrantObject::Database(_db_id) => {
                if let Some(db) = &mut self.database {
                    db.grant_privileges(privileges, grant_on);
                } else {
                    self.database = Some(ShareGrantEntry::new(object, privileges, grant_on));
                }
            }
            ShareGrantObject::Table(_table_id) => {
                match self.entries.get_mut(&key) {
                    Some(entry) => {
                        entry.grant_privileges(privileges, grant_on);
                    }
                    None => {
                        let entry = ShareGrantEntry::new(object, privileges, grant_on);
                        self.entries.insert(key, entry);
                    }
                };
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareIdent {
    pub share_id: u64,
    pub seq: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareInfo {
    pub ident: ShareIdent,
    pub name_ident: ShareNameIdent,
    pub meta: ShareMeta,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareTableSpec {
    pub name: String,
    pub database_id: u64,
    pub table_id: u64,
    pub presigned_url_timeout: String,
}

impl ShareTableSpec {
    pub fn new(name: &str, database_id: u64, table_id: u64) -> Self {
        ShareTableSpec {
            name: name.to_owned(),
            database_id,
            table_id,
            presigned_url_timeout: "120s".to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareDatabaseSpec {
    pub name: String,
    pub id: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareSpec {
    pub name: String,
    pub share_id: u64,
    pub version: u64,
    pub database: Option<ShareDatabaseSpec>,
    pub tables: Vec<ShareTableSpec>,
    pub tenants: Vec<String>,
    pub db_privileges: Option<BitFlags<ShareGrantObjectPrivilege>>,
    pub comment: Option<String>,
    pub share_on: Option<DateTime<Utc>>,
}

mod kvapi_key_impl {
    use common_meta_kvapi::kvapi;

    use super::ShareEndpointId;
    use crate::share::ShareAccountNameIdent;
    use crate::share::ShareEndpointIdToName;
    use crate::share::ShareEndpointIdent;
    use crate::share::ShareGrantObject;
    use crate::share::ShareId;
    use crate::share::ShareIdToName;
    use crate::share::ShareNameIdent;

    const PREFIX_SHARE: &str = "__fd_share";
    const PREFIX_SHARE_BY: &str = "__fd_share_by";
    const PREFIX_SHARE_ID: &str = "__fd_share_id";
    const PREFIX_SHARE_ID_TO_NAME: &str = "__fd_share_id_to_name";
    const PREFIX_SHARE_ACCOUNT_ID: &str = "__fd_share_account_id";
    const PREFIX_SHARE_ENDPOINT: &str = "__fd_share_endpoint";
    const PREFIX_SHARE_ENDPOINT_ID: &str = "__fd_share_endpoint_id";
    const PREFIX_SHARE_ENDPOINT_ID_TO_NAME: &str = "__fd_share_endpoint_id_to_name";

    /// __fd_share_by/{db|table}/<object_id> -> ObjectSharedByShareIds
    impl kvapi::Key for ShareGrantObject {
        const PREFIX: &'static str = PREFIX_SHARE_BY;

        fn to_string_key(&self) -> String {
            match *self {
                ShareGrantObject::Database(db_id) => kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                    .push_raw("db")
                    .push_u64(db_id)
                    .done(),
                ShareGrantObject::Table(table_id) => kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                    .push_raw("table")
                    .push_u64(table_id)
                    .done(),
            }
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let kind = p.next_raw()?;
            let id = p.next_u64()?;
            p.done()?;

            if kind == "db" {
                Ok(ShareGrantObject::Database(id))
            } else if kind == "table" {
                Ok(ShareGrantObject::Table(id))
            } else {
                return Err(kvapi::KeyError::InvalidSegment {
                    i: 1,
                    expect: "db or table".to_string(),
                    got: kind.to_string(),
                });
            }
        }
    }

    /// __fd_share/<tenant>/<share_name> -> <share_id>
    impl kvapi::Key for ShareNameIdent {
        const PREFIX: &'static str = PREFIX_SHARE;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_str(&self.tenant)
                .push_str(&self.share_name)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let tenant = p.next_str()?;
            let share_name = p.next_str()?;
            p.done()?;

            Ok(ShareNameIdent { tenant, share_name })
        }
    }

    /// __fd_share_id/<share_id> -> <share_meta>
    impl kvapi::Key for ShareId {
        const PREFIX: &'static str = PREFIX_SHARE_ID;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_u64(self.share_id)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let share_id = p.next_u64()?;
            p.done()?;

            Ok(ShareId { share_id })
        }
    }

    // __fd_share_account/tenant/id -> ShareAccountMeta
    impl kvapi::Key for ShareAccountNameIdent {
        const PREFIX: &'static str = PREFIX_SHARE_ACCOUNT_ID;

        fn to_string_key(&self) -> String {
            if self.share_id != 0 {
                kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                    .push_str(&self.account)
                    .push_u64(self.share_id)
                    .done()
            } else {
                kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                    .push_str(&self.account)
                    .done()
            }
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let account = p.next_str()?;
            let share_id = p.next_u64()?;
            p.done()?;

            Ok(ShareAccountNameIdent { account, share_id })
        }
    }

    /// __fd_share_id_to_name/<share_id> -> ShareNameIdent
    impl kvapi::Key for ShareIdToName {
        const PREFIX: &'static str = PREFIX_SHARE_ID_TO_NAME;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_u64(self.share_id)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let share_id = p.next_u64()?;
            p.done()?;

            Ok(ShareIdToName { share_id })
        }
    }

    /// __fd_share/<tenant>/<share_endpoint_name> -> ShareEndpointId
    impl kvapi::Key for ShareEndpointIdent {
        const PREFIX: &'static str = PREFIX_SHARE_ENDPOINT;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_str(&self.tenant)
                .push_str(&self.endpoint)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let tenant = p.next_str()?;
            let endpoint = p.next_str()?;
            p.done()?;

            Ok(ShareEndpointIdent { tenant, endpoint })
        }
    }

    /// __fd_share_endpoint_id/<share_endpoint_id> -> <share_meta>
    impl kvapi::Key for ShareEndpointId {
        const PREFIX: &'static str = PREFIX_SHARE_ENDPOINT_ID;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_u64(self.share_endpoint_id)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let share_endpoint_id = p.next_u64()?;
            p.done()?;

            Ok(ShareEndpointId { share_endpoint_id })
        }
    }

    /// __fd_share_endpoint_id_to_name/<share_endpoint_id> -> ShareEndpointIdent
    impl kvapi::Key for ShareEndpointIdToName {
        const PREFIX: &'static str = PREFIX_SHARE_ENDPOINT_ID_TO_NAME;

        fn to_string_key(&self) -> String {
            kvapi::KeyBuilder::new_prefixed(Self::PREFIX)
                .push_u64(self.share_endpoint_id)
                .done()
        }

        fn from_str_key(s: &str) -> Result<Self, kvapi::KeyError> {
            let mut p = kvapi::KeyParser::new_prefixed(s, Self::PREFIX)?;

            let share_endpoint_id = p.next_u64()?;
            p.done()?;

            Ok(ShareEndpointIdToName { share_endpoint_id })
        }
    }
}
