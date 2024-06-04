use clap::Parser;
use clap_stdin::FileOrStdin;
use cosmwasm_std::Event;
use events::kms::{KmsEvent, KmsMessage, KmsOperation, OperationValue};
use events::HexVector;
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest};
use kms_blockchain_client::query_client::{
    ContractQuery, OperationQuery, QueryClient, QueryClientBuilder, QueryContractRequest,
};
use simulator::conf::{Settings, SimConfig};
use std::error::Error;
use strum::IntoEnumIterator;

#[derive(Debug, Parser)]
struct Execute {
    #[clap(long, short = 'm')]
    file_stdin: FileOrStdin,
}

#[derive(Debug, Parser)]
struct Query {
    #[clap(long, short = 't')]
    txn_id: String,
    #[clap(long, short = 'p')]
    proof: String,
    #[clap(long, short = 'o')]
    event: KmsOperation,
}

#[derive(Debug, Parser)]
enum Command {
    ExecuteContract(Execute),
    QueryContract(Query),
}

#[derive(Debug, Parser)]
struct Config {
    #[clap(long, short = 'f')]
    file_conf: Option<String>,
    #[clap(subcommand)]
    command: Command,
}

fn to_event(event: &cosmos_proto::messages::tendermint::abci::Event) -> Event {
    let mut result = Event::new(event.r#type.clone());
    for attribute in event.attributes.iter() {
        let key = attribute.key.clone();
        let value = attribute.value.clone();
        result = result.add_attribute(key, value);
    }
    result
}

async fn execute_contract(
    file: FileOrStdin,
    client: Client,
    query_client: QueryClient,
) -> Result<(), Box<dyn Error + 'static>> {
    let mut client = client;
    let msg = file.contents()?;
    let value = serde_json::from_str::<OperationValue>(&msg)?;

    let request = ExecuteContractRequest::builder()
        .message(
            KmsMessage::builder()
                .proof(vec![1, 2, 3])
                .value(value)
                .build(),
        )
        .gas_limit(200_000)
        .build();

    let response = client.execute_contract(request).await?;

    let resp;
    loop {
        let query_response = query_client.query_tx(response.txhash.clone()).await?;
        if let Some(qr) = query_response {
            resp = qr;
            break;
        } else {
            tracing::warn!("Waiting for transaction to be included in a block");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            continue;
        }
    }
    let evs: Vec<KmsEvent> = resp
        .events
        .iter()
        .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
        .map(to_event)
        .map(<Event as TryInto<KmsEvent>>::try_into)
        .collect::<Result<Vec<KmsEvent>, _>>()?;

    let ev = evs[0].clone();

    tracing::info!(
        "TxId: {:?} - Proof: {:?}",
        ev.txn_id().to_hex(),
        ev.proof().to_hex()
    );
    Ok(())
}

async fn query_contract(
    sim_config: SimConfig,
    query: Query,
    query_client: QueryClient,
) -> Result<(), Box<dyn Error + 'static>> {
    let txn_id = HexVector::from_hex(&query.txn_id)?;
    let proof = HexVector::from_hex(&query.proof)?;
    let ev = KmsEvent::builder()
        .operation(query.event)
        .txn_id(txn_id)
        .proof(proof)
        .build();
    let query_req = ContractQuery::GetOperationsValue(OperationQuery::builder().event(ev).build());

    let request = QueryContractRequest::builder()
        .contract_address(sim_config.contract)
        .query(query_req)
        .build();
    let value: Vec<OperationValue> = query_client.query_contract(request).await?;

    tracing::info!("Value: {:?}", value);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let config = Config::parse();
    let settings = Settings {
        path: config.file_conf.as_deref(),
    };
    let sim_conf = settings.init_conf()?;
    let grpc_addresses = sim_conf
        .addresses
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<&str>>();
    let client: Client = ClientBuilder::builder()
        .grpc_addresses(grpc_addresses.clone())
        .contract_address(&sim_conf.contract)
        .mnemonic_wallet(Some(&sim_conf.mnemonic))
        .build()
        .try_into()?;

    let query_client: QueryClient = QueryClientBuilder::builder()
        .grpc_addresses(grpc_addresses)
        .build()
        .try_into()?;

    match config.command {
        Command::ExecuteContract(ex) => {
            execute_contract(ex.file_stdin, client, query_client).await?
        }
        Command::QueryContract(q) => query_contract(sim_conf, q, query_client).await?,
    }

    Ok(())
}
