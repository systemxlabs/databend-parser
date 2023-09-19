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
use std::fmt::Display;
use std::fmt::Formatter;

use crate::meta::CatalogType;

use super::ShowLimit;
use crate::ast::Identifier;

#[derive(Debug, Clone, PartialEq)]
pub struct ShowCatalogsStmt {
    pub limit: Option<ShowLimit>,
}

impl Display for ShowCatalogsStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHOW CATALOGS")?;
        if let Some(limit) = &self.limit {
            write!(f, " {}", limit)?
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShowCreateCatalogStmt {
    pub catalog: Identifier,
}

impl Display for ShowCreateCatalogStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHOW CREATE CATALOG {}", &self.catalog)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCatalogStmt {
    pub if_not_exists: bool,
    pub catalog_name: String,
    pub catalog_type: CatalogType,
    pub catalog_options: BTreeMap<String, String>,
}

impl Display for CreateCatalogStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CREATE CATALOG")?;
        if self.if_not_exists {
            write!(f, " IF NOT EXISTS")?;
        }
        write!(f, " {}", self.catalog_name)?;
        write!(f, " TYPE='{}'", self.catalog_type)?;
        write!(f, " CONNECTION = (")?;
        for (k, v) in self.catalog_options.iter() {
            write!(f, " {}='{}'", k, v)?;
        }
        write!(f, " )")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropCatalogStmt {
    pub if_exists: bool,
    pub catalog: Identifier,
}

impl Display for DropCatalogStmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DROP CATALOG ")?;
        if self.if_exists {
            write!(f, "IF EXISTS ")?;
        }
        write!(f, "{}", self.catalog)
    }
}
