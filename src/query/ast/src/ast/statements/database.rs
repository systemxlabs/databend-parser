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

use crate::meta::ShareNameIdent;

use crate::ast::statements::show::ShowLimit;
use crate::ast::write_dot_separated_list;
use crate::ast::Identifier;

#[derive(Debug, Clone, PartialEq)] // Databases
pub struct ShowDatabasesStmt {
    pub catalog: Option<Identifier>,
    pub full: bool,
    pub limit: Option<ShowLimit>,
}

impl Display for ShowDatabasesStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHOW ")?;
        if self.full {
            write!(f, "FULL ")?;
        }
        write!(f, "DATABASES")?;
        if let Some(catalog) = &self.catalog {
            write!(f, " FROM {catalog}")?;
        }
        if let Some(limit) = &self.limit {
            write!(f, " {limit}")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowCreateDatabaseStmt {
    pub catalog: Option<Identifier>,
    pub database: Identifier,
}

impl Display for ShowCreateDatabaseStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHOW CREATE DATABASE ")?;
        write_dot_separated_list(f, self.catalog.iter().chain(Some(&self.database)))?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDatabaseStmt {
    pub if_not_exists: bool,
    pub catalog: Option<Identifier>,
    pub database: Identifier,
    pub engine: Option<DatabaseEngine>,
    pub options: Vec<SQLProperty>,
    pub from_share: Option<ShareNameIdent>,
}

impl Display for CreateDatabaseStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CREATE DATABASE ")?;
        if self.if_not_exists {
            write!(f, "IF NOT EXISTS ")?;
        }
        write_dot_separated_list(f, self.catalog.iter().chain(Some(&self.database)))?;
        if let Some(engine) = &self.engine {
            write!(f, " ENGINE = {engine}")?;
        }
        if let Some(from_share) = &self.from_share {
            write!(
                f,
                " FROM SHARE {}.{}",
                from_share.tenant, from_share.share_name
            )?;
        }
        // TODO(leiysky): display rest information
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropDatabaseStmt {
    pub if_exists: bool,
    pub catalog: Option<Identifier>,
    pub database: Identifier,
}

impl Display for DropDatabaseStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DROP DATABASE ")?;
        if self.if_exists {
            write!(f, "IF EXISTS ")?;
        }
        write_dot_separated_list(f, self.catalog.iter().chain(Some(&self.database)))?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndropDatabaseStmt {
    pub catalog: Option<Identifier>,
    pub database: Identifier,
}

impl Display for UndropDatabaseStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UNDROP DATABASE ")?;
        write_dot_separated_list(f, self.catalog.iter().chain(Some(&self.database)))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlterDatabaseStmt {
    pub if_exists: bool,
    pub catalog: Option<Identifier>,
    pub database: Identifier,
    pub action: AlterDatabaseAction,
}

impl Display for AlterDatabaseStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ALTER DATABASE ")?;
        if self.if_exists {
            write!(f, "IF EXISTS ")?;
        }
        write_dot_separated_list(f, self.catalog.iter().chain(Some(&self.database)))?;
        match &self.action {
            AlterDatabaseAction::RenameDatabase { new_db } => {
                write!(f, " RENAME TO {new_db}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlterDatabaseAction {
    RenameDatabase { new_db: Identifier },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseEngine {
    Default,
    Share,
}

impl Display for DatabaseEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseEngine::Default => write!(f, "DEFAULT"),
            DatabaseEngine::Share => write!(f, "SHARE"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SQLProperty {
    pub name: String,
    pub value: String,
}
