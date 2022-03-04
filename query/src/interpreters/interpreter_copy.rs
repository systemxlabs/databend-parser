// Copyright 2021 Datafuse Labs.
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

use std::sync::Arc;

use common_exception::ErrorCode;
use common_exception::Result;
use common_io::prelude::S3File;
use common_meta_types::StageStorage;
use common_planners::CopyPlan;
use common_planners::PlanNode;
use common_planners::ReadDataSourcePlan;
use common_planners::SourceInfo;
use common_streams::DataBlockStream;
use common_streams::ProgressStream;
use common_streams::SendableDataBlockStream;
use common_tracing::tracing;
use futures::TryStreamExt;

use crate::interpreters::stream::ProcessorExecutorStream;
use crate::interpreters::Interpreter;
use crate::interpreters::InterpreterPtr;
use crate::pipelines::new::executor::PipelinePullingExecutor;
use crate::pipelines::new::QueryPipelineBuilder;
use crate::sessions::QueryContext;

pub struct CopyInterpreter {
    ctx: Arc<QueryContext>,
    plan: CopyPlan,
}

impl CopyInterpreter {
    pub fn try_create(ctx: Arc<QueryContext>, plan: CopyPlan) -> Result<InterpreterPtr> {
        Ok(Arc::new(CopyInterpreter { ctx, plan }))
    }

    // List the files under a folder.
    async fn list_files(&self) -> Result<Vec<String>> {
        // We already set the files sets to the COPY command with: `files=(<file1>, <file2>)` syntax.
        if !self.plan.files.is_empty() {
            return Ok(self.plan.files.clone());
        }

        let files = match &self.plan.from.source_info {
            SourceInfo::S3ExternalSource(table_info) => {
                let storage = &table_info.stage_info.stage_params.storage;
                match &storage {
                    StageStorage::S3(s3) => {
                        let endpoint = &self.ctx.get_config().storage.s3.endpoint_url;
                        let bucket = &s3.bucket;
                        let path = &s3.path;

                        let key_id = &s3.credentials_aws_key_id;
                        let secret_key = &s3.credentials_aws_secret_key;

                        S3File::list(endpoint, bucket, path, key_id, secret_key).await
                    }
                }
            }
            other => Err(ErrorCode::LogicalError(format!(
                "Cannot list files for the source info: {:?}",
                other
            ))),
        };

        files
    }

    // Rewrite the ReadDataSourcePlan.S3ExternalSource.file_name to new file name.
    fn rewrite_read_plan_file_name(
        mut plan: ReadDataSourcePlan,
        file_name: Option<String>,
    ) -> ReadDataSourcePlan {
        if let SourceInfo::S3ExternalSource(ref mut s3) = plan.source_info {
            s3.file_name = file_name;
        }
        plan
    }

    // Read a file and commit it to the table.
    // Progress:
    // 1. Build a select pipeline
    // 2. Execute the pipeline and get the stream
    // 3. Read from the stream and write to the table.
    // Note:
    //  We parse the `s3://` to ReadSourcePlan instead of to a SELECT plan is that:
    //  COPY should deal with the file one by one and do some error handler on the OnError strategy.

    #[tracing::instrument(level = "debug", name = "copy_one_file_to_table", skip(self), fields(ctx.id = self.ctx.get_id().as_str()))]
    async fn copy_one_file_to_table(&self, file_name: Option<String>) -> Result<()> {
        let ctx = self.ctx.clone();
        let settings = self.ctx.get_settings();

        let read_source_plan = self.plan.from.clone();
        let read_source_plan = Self::rewrite_read_plan_file_name(read_source_plan, file_name);

        tracing::info!("copy_one_file_to_table: source plan:{:?}", read_source_plan);

        let from_plan = common_planners::SelectPlan {
            input: Arc::new(PlanNode::ReadSource(read_source_plan)),
        };

        let pipeline_builder = QueryPipelineBuilder::create(ctx.clone());
        let mut pipeline = pipeline_builder.finalize(&from_plan)?;
        pipeline.set_max_threads(settings.get_max_threads()? as usize);

        let executor = PipelinePullingExecutor::try_create(pipeline)?;
        let source_stream = Box::pin(ProcessorExecutorStream::create(executor)?);
        let progress_stream = Box::pin(ProgressStream::try_create(
            source_stream,
            ctx.get_scan_progress(),
        )?);

        let table = ctx
            .get_table(&self.plan.db_name, &self.plan.tbl_name)
            .await?;
        let operations = table
            .append_data(ctx.clone(), progress_stream)
            .await?
            .try_collect()
            .await?;

        // Commit.
        table
            .commit_insertion(ctx.clone(), operations, false)
            .await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl Interpreter for CopyInterpreter {
    fn name(&self) -> &str {
        "CopyInterpreter"
    }

    #[tracing::instrument(level = "debug", name = "copy_interpreter_execute", skip(self, _input_stream), fields(ctx.id = self.ctx.get_id().as_str()))]
    async fn execute(
        &self,
        mut _input_stream: Option<SendableDataBlockStream>,
    ) -> Result<SendableDataBlockStream> {
        let files = self.list_files().await?;
        for file in files {
            self.copy_one_file_to_table(Some(file)).await?;
        }

        Ok(Box::pin(DataBlockStream::create(
            self.plan.schema(),
            None,
            vec![],
        )))
    }
}
