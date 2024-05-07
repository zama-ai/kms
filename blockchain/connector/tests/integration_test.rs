//use kms_blockchain_connector::application::sync_handler::SyncHandler;
//use kms_blockchain_connector::conf::{ConnectorConfig, Settings};
//use test_context::{test_context, AsyncTestContext};
//use test_utilities::context::DockerCompose;

//struct DockerComposeContext {
//    cmd: DockerCompose,
//}
//
//impl AsyncTestContext for DockerComposeContext {
//    async fn setup() -> Self {
//        DockerComposeContext {
//            cmd: DockerCompose::new("tests/docker-compose.yml"),
//        }
//    }
//
//    async fn teardown(self) {
//        drop(self.cmd);
//    }
//}
//
//#[test_context(DockerComposeContext)]
//#[tokio::test]
//async fn hello_world_test(_ctx: &mut DockerComposeContext) {
//    let settings = Settings::builder().path(None).build();
//    let config: ConnectorConfig = settings.init_conf().unwrap();
//
//    let handler = SyncHandler::new_with_config(config).await.unwrap();
//
//    handler.listen_for_events().await.unwrap();
//}
