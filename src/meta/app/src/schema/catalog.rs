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
use std::ops::Deref;

use chrono::DateTime;
use chrono::Utc;

use crate::storage::StorageParams;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CatalogType {
    Default = 1,
    Hive = 2,
    Iceberg = 3,
}

impl Display for CatalogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogType::Default => write!(f, "DEFAULT"),
            CatalogType::Hive => write!(f, "HIVE"),
            CatalogType::Iceberg => write!(f, "ICEBERG"),
        }
    }
}

/// different options for creating catalogs
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CatalogOption {
    /// The default catalog.
    ///
    /// It's not allowed to create a new default catalog.
    Default,
    // Catalog option for hive.
    Hive(HiveCatalogOption),
    // Catalog option for Iceberg.
    Iceberg(IcebergCatalogOption),
}

impl CatalogOption {
    pub fn catalog_type(&self) -> CatalogType {
        match self {
            CatalogOption::Default => CatalogType::Default,
            CatalogOption::Hive(_) => CatalogType::Hive,
            CatalogOption::Iceberg(_) => CatalogType::Iceberg,
        }
    }
}

/// Option for creating a iceberg catalog
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HiveCatalogOption {
    pub address: String,
    pub storage_params: Option<Box<StorageParams>>,
}

/// Option for creating a iceberg catalog
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IcebergCatalogOption {
    pub storage_params: Box<StorageParams>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CatalogInfo {
    pub id: CatalogId,
    pub name_ident: CatalogNameIdent,
    pub meta: CatalogMeta,
}

impl CatalogInfo {
    /// Get the catalog type via catalog info.
    pub fn catalog_type(&self) -> CatalogType {
        self.meta.catalog_option.catalog_type()
    }

    /// Get the catalog name via catalog info.
    pub fn catalog_name(&self) -> &str {
        &self.name_ident.catalog_name
    }

    /// Create a new default catalog info.
    pub fn new_default() -> CatalogInfo {
        Self {
            id: CatalogId { catalog_id: 0 },
            name_ident: CatalogNameIdent {
                // tenant for default catalog is not used.
                tenant: "".to_string(),
                catalog_name: "default".to_string(),
            },
            meta: CatalogMeta {
                catalog_option: CatalogOption::Default,
                created_on: Default::default(),
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CatalogMeta {
    pub catalog_option: CatalogOption,
    pub created_on: DateTime<Utc>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CatalogNameIdent {
    pub tenant: String,
    pub catalog_name: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogId {
    pub catalog_id: u64,
}

impl Display for CatalogNameIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}'/'{}'", self.tenant, self.catalog_name)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct CatalogIdToName {
    pub catalog_id: u64,
}

impl Display for CatalogIdToName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.catalog_id)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateCatalogReq {
    pub if_not_exists: bool,
    pub name_ident: CatalogNameIdent,
    pub meta: CatalogMeta,
}

impl CreateCatalogReq {
    pub fn tenant(&self) -> &str {
        &self.name_ident.tenant
    }
    pub fn catalog_name(&self) -> &str {
        &self.name_ident.catalog_name
    }
}

impl Display for CreateCatalogReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "create_catalog(if_not_exists={}):{}/{}={:?}",
            self.if_not_exists, self.name_ident.tenant, self.name_ident.catalog_name, self.meta
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CreateCatalogReply {
    pub catalog_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropCatalogReq {
    pub if_exists: bool,
    pub name_ident: CatalogNameIdent,
}

impl Display for DropCatalogReq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "drop_catalog(if_exists={}):{}/{}",
            self.if_exists, self.name_ident.tenant, self.name_ident.catalog_name
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DropCatalogReply {}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GetCatalogReq {
    pub inner: CatalogNameIdent,
}

impl Deref for GetCatalogReq {
    type Target = CatalogNameIdent;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl GetCatalogReq {
    pub fn new(tenant: impl Into<String>, catalog_name: impl Into<String>) -> GetCatalogReq {
        GetCatalogReq {
            inner: CatalogNameIdent {
                tenant: tenant.into(),
                catalog_name: catalog_name.into(),
            },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ListCatalogReq {
    pub tenant: String,
}

impl ListCatalogReq {
    pub fn new(tenant: impl Into<String>) -> ListCatalogReq {
        ListCatalogReq {
            tenant: tenant.into(),
        }
    }
}