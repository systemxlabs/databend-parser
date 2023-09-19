use std::collections::BTreeMap;

use common_exception::ErrorCode;
use common_exception::Result;
use serde::{Deserialize, Serialize};
use enumflags2::BitFlags;
use enumflags2::bitflags;

pub mod user_identity;
pub mod principal_identity;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CatalogType {
    Default = 1,
    Hive = 2,
    Iceberg = 3,
}

impl std::fmt::Display for CatalogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogType::Default => write!(f, "DEFAULT"),
            CatalogType::Hive => write!(f, "HIVE"),
            CatalogType::Iceberg => write!(f, "ICEBERG"),
        }
    }
}


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ShareNameIdent {
    pub tenant: String,
    pub share_name: String,
}

impl std::fmt::Display for ShareNameIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'/'{}'", self.tenant, self.share_name)
    }
}


#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ShareGrantObjectName {
    // database name
    Database(String),
    // database name, table name
    Table(String, String),
}

impl std::fmt::Display for ShareGrantObjectName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Display for ShareGrantObjectPrivilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ShareGrantObjectPrivilege::Usage => write!(f, "USAGE"),
            ShareGrantObjectPrivilege::ReferenceUsage => write!(f, "REFERENCE_USAGE"),
            ShareGrantObjectPrivilege::Select => write!(f, "SELECT"),
        }
    }
}


const NO_PASSWORD_STR: &str = "no_password";
const SHA256_PASSWORD_STR: &str = "sha256_password";
const DOUBLE_SHA1_PASSWORD_STR: &str = "double_sha1_password";
const JWT_AUTH_STR: &str = "jwt";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum AuthType {
    NoPassword,
    Sha256Password,
    DoubleSha1Password,
    JWT,
}

impl std::str::FromStr for AuthType {
    type Err = ErrorCode;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            SHA256_PASSWORD_STR => Ok(AuthType::Sha256Password),
            DOUBLE_SHA1_PASSWORD_STR => Ok(AuthType::DoubleSha1Password),
            NO_PASSWORD_STR => Ok(AuthType::NoPassword),
            JWT_AUTH_STR => Ok(AuthType::JWT),
            _ => Err(ErrorCode::InvalidAuthInfo(AuthType::bad_auth_types(s))),
        }
    }
}

impl AuthType {
    pub fn to_str(&self) -> &str {
        match self {
            AuthType::NoPassword => NO_PASSWORD_STR,
            AuthType::Sha256Password => SHA256_PASSWORD_STR,
            AuthType::DoubleSha1Password => DOUBLE_SHA1_PASSWORD_STR,
            AuthType::JWT => JWT_AUTH_STR,
        }
    }

    fn bad_auth_types(s: &str) -> String {
        let all = vec![
            NO_PASSWORD_STR,
            SHA256_PASSWORD_STR,
            DOUBLE_SHA1_PASSWORD_STR,
            JWT_AUTH_STR,
        ];
        let all = all
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join("|");
        format!("Expected auth type {}, found: {}", all, s)
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFormatOptionsAst {
    pub options: BTreeMap<String, String>,
}

impl std::fmt::Display for FileFormatOptionsAst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.options)
    }
}

impl FileFormatOptionsAst {
    pub fn new(options: BTreeMap<String, String>) -> Self {
        FileFormatOptionsAst { options }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(default)]
pub struct UserOption {
    flags: BitFlags<UserOptionFlag>,

    default_role: Option<String>,

    network_policy: Option<String>,
}

impl UserOption {
    pub fn new(flags: BitFlags<UserOptionFlag>) -> Self {
        Self {
            flags,
            default_role: None,
            network_policy: None,
        }
    }

    pub fn empty() -> Self {
        Default::default()
    }

    pub fn with_flags(mut self, flags: BitFlags<UserOptionFlag>) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_default_role(mut self, default_role: Option<String>) -> Self {
        self.default_role = default_role;
        self
    }

    pub fn with_network_policy(mut self, network_policy: Option<String>) -> Self {
        self.network_policy = network_policy;
        self
    }

    pub fn with_set_flag(mut self, flag: UserOptionFlag) -> Self {
        self.flags.insert(flag);
        self
    }

    pub fn flags(&self) -> &BitFlags<UserOptionFlag> {
        &self.flags
    }

    pub fn default_role(&self) -> Option<&String> {
        self.default_role.as_ref()
    }

    pub fn network_policy(&self) -> Option<&String> {
        self.network_policy.as_ref()
    }

    pub fn set_default_role(&mut self, default_role: Option<String>) {
        self.default_role = default_role;
    }

    pub fn set_network_policy(&mut self, network_policy: Option<String>) {
        self.network_policy = network_policy;
    }

    pub fn set_all_flag(&mut self) {
        self.flags = BitFlags::all();
    }

    pub fn set_option_flag(&mut self, flag: UserOptionFlag) {
        self.flags.insert(flag);
    }

    pub fn switch_option_flag(&mut self, flag: UserOptionFlag, on: bool) {
        if on {
            self.flags.insert(flag);
        } else {
            self.flags.remove(flag);
        }
    }

    pub fn unset_option_flag(&mut self, flag: UserOptionFlag) {
        self.flags.remove(flag);
    }

    pub fn has_option_flag(&self, flag: UserOptionFlag) -> bool {
        self.flags.contains(flag)
    }
}

#[bitflags]
#[repr(u64)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, num_derive::FromPrimitive)]
pub enum UserOptionFlag {
    TenantSetting = 1 << 0,
}

impl std::fmt::Display for UserOptionFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserOptionFlag::TenantSetting => write!(f, "TENANTSETTING"),
        }
    }
}


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
pub enum UserPrivilegeType {
    // UsagePrivilege is a synonym for “no privileges”
    Usage = 1 << 0,
    // Privilege to select rows from tables in a database.
    Select = 1 << 2,
    // Privilege to insert into tables in a database.
    Insert = 1 << 3,
    // Privilege to update rows in a table
    Update = 1 << 5,
    // Privilege to delete rows in a table
    Delete = 1 << 6,
    // Privilege to create databases or tables.
    Create = 1 << 1,
    // Privilege to drop databases or tables.
    Drop = 1 << 7,
    // Privilege to alter databases or tables.
    Alter = 1 << 8,
    // Privilege to Kill query, Set global configs, etc.
    Super = 1 << 9,
    // Privilege to Create User.
    CreateUser = 1 << 10,
    // Privilege to Create Role.
    CreateRole = 1 << 11,
    // Privilege to Grant/Revoke privileges to users or roles
    Grant = 1 << 12,
    // Privilege to Create Stage.
    CreateStage = 1 << 13,
    // Privilege to Drop role.
    DropRole = 1 << 14,
    // Privilege to Drop user.
    DropUser = 1 << 15,
    // Privilege to Create/Drop DataMask.
    CreateDataMask = 1 << 16,
    // Privilege to Own a databend object such as database/table.
    Ownership = 1 << 17,
    // TODO: remove this later
    Set = 1 << 4,
}
impl std::fmt::Display for UserPrivilegeType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", match self {
            UserPrivilegeType::Usage => "USAGE",
            UserPrivilegeType::Create => "CREATE",
            UserPrivilegeType::Update => "UPDATE",
            UserPrivilegeType::Select => "SELECT",
            UserPrivilegeType::Insert => "INSERT",
            UserPrivilegeType::Delete => "DELETE",
            UserPrivilegeType::Drop => "DROP",
            UserPrivilegeType::Alter => "ALTER",
            UserPrivilegeType::Super => "SUPER",
            UserPrivilegeType::CreateUser => "CREATE USER",
            UserPrivilegeType::DropUser => "DROP USER",
            UserPrivilegeType::CreateRole => "CREATE ROLE",
            UserPrivilegeType::DropRole => "DROP ROLE",
            UserPrivilegeType::CreateStage => "CREATE STAGE",
            UserPrivilegeType::Grant => "GRANT",
            UserPrivilegeType::Set => "SET",
            UserPrivilegeType::CreateDataMask => "CREATE DATAMASK",
            UserPrivilegeType::Ownership => "OWNERSHIP",
        })
    }
}