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

use crate::meta::AuthType;
use crate::meta::principal_identity::PrincipalIdentity;
use crate::meta::user_identity::UserIdentity;
use crate::meta::UserOption;
use crate::meta::UserOptionFlag;
use crate::meta::UserPrivilegeType;

use crate::ast::write_comma_separated_list;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserStmt {
    pub if_not_exists: bool,
    pub user: UserIdentity,
    pub auth_option: AuthOption,
    pub user_options: Vec<UserOptionItem>,
}

impl Display for CreateUserStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CREATE USER")?;
        if self.if_not_exists {
            write!(f, " IF NOT EXISTS")?;
        }
        write!(f, " {} IDENTIFIED", self.user)?;
        write!(f, " {}", self.auth_option)?;
        if !self.user_options.is_empty() {
            write!(f, " WITH")?;
            for user_option in &self.user_options {
                write!(f, " {user_option}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthOption {
    pub auth_type: Option<AuthType>,
    pub password: Option<String>,
}

impl Display for AuthOption {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(auth_type) = &self.auth_type {
            write!(f, "WITH {} ", auth_type.to_str())?;
        }
        if let Some(password) = &self.password {
            write!(f, "BY '{password}'")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlterUserStmt {
    // None means current user
    pub user: Option<UserIdentity>,
    // None means no change to make
    pub auth_option: Option<AuthOption>,
    pub user_options: Vec<UserOptionItem>,
}

impl Display for AlterUserStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ALTER USER")?;
        if let Some(user) = &self.user {
            write!(f, " {user}")?;
        } else {
            write!(f, " USER()")?;
        }
        if let Some(auth_option) = &self.auth_option {
            write!(f, " IDENTIFIED {}", auth_option)?;
        }
        if !self.user_options.is_empty() {
            write!(f, " WITH")?;
            for with_option in &self.user_options {
                write!(f, " {with_option}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantStmt {
    pub source: AccountMgrSource,
    pub principal: PrincipalIdentity,
}

impl Display for GrantStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GRANT")?;
        write!(f, "{}", self.source)?;

        write!(f, " TO")?;
        write!(f, "{}", self.principal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeStmt {
    pub source: AccountMgrSource,
    pub principal: PrincipalIdentity,
}

impl Display for RevokeStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "REVOKE")?;
        write!(f, "{}", self.source)?;

        write!(f, " FROM")?;
        write!(f, "{}", self.principal)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountMgrSource {
    Role {
        role: String,
    },
    Privs {
        privileges: Vec<UserPrivilegeType>,
        level: AccountMgrLevel,
    },
    ALL {
        level: AccountMgrLevel,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountMgrLevel {
    Global,
    Database(Option<String>),
    Table(Option<String>, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserOptionItem {
    TenantSetting(bool),
    DefaultRole(String),
    SetNetworkPolicy(String),
    UnsetNetworkPolicy,
}

impl UserOptionItem {
    pub fn apply(&self, option: &mut UserOption) {
        match self {
            Self::TenantSetting(enabled) => {
                option.switch_option_flag(UserOptionFlag::TenantSetting, *enabled);
            }
            Self::DefaultRole(v) => option.set_default_role(Some(v.clone())),
            Self::SetNetworkPolicy(v) => option.set_network_policy(Some(v.clone())),
            Self::UnsetNetworkPolicy => option.set_network_policy(None),
        }
    }
}

impl Display for AccountMgrSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountMgrSource::Role { role } => write!(f, " ROLE {role}")?,
            AccountMgrSource::Privs { privileges, level } => {
                write!(f, " ")?;
                write_comma_separated_list(f, privileges.iter().map(|p| p.to_string()))?;
                write!(f, " ON")?;
                match level {
                    AccountMgrLevel::Global => write!(f, " *.*")?,
                    AccountMgrLevel::Database(database_name) => {
                        if let Some(database_name) = database_name {
                            write!(f, " {database_name}.*")?;
                        } else {
                            write!(f, " *")?;
                        }
                    }
                    AccountMgrLevel::Table(database_name, table_name) => {
                        if let Some(database_name) = database_name {
                            write!(f, " {database_name}.{table_name}")?;
                        } else {
                            write!(f, " {table_name}")?;
                        }
                    }
                }
            }
            AccountMgrSource::ALL { level, .. } => {
                write!(f, " ALL PRIVILEGES")?;
                write!(f, " ON")?;
                match level {
                    AccountMgrLevel::Global => write!(f, " *.*")?,
                    AccountMgrLevel::Database(database_name) => {
                        if let Some(database_name) = database_name {
                            write!(f, " {database_name}.*")?;
                        } else {
                            write!(f, " *")?;
                        }
                    }
                    AccountMgrLevel::Table(database_name, table_name) => {
                        if let Some(database_name) = database_name {
                            write!(f, " {database_name}.{table_name}")?;
                        } else {
                            write!(f, " {table_name}")?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Display for UserOptionItem {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            UserOptionItem::TenantSetting(true) => write!(f, "TENANTSETTING"),
            UserOptionItem::TenantSetting(false) => write!(f, "NOTENANTSETTING"),
            UserOptionItem::DefaultRole(v) => write!(f, "DEFAULT_ROLE = '{}'", v),
            UserOptionItem::SetNetworkPolicy(v) => write!(f, "SET NETWORK POLICY = '{}'", v),
            UserOptionItem::UnsetNetworkPolicy => write!(f, "UNSET NETWORK POLICY"),
        }
    }
}
