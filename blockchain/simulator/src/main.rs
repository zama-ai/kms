use bincode::deserialize;
use clap::Parser;
use conf_trace::conf::Settings;
use cosmwasm_std::Event;
use events::kms::{DecryptValues, FheType, KmsEvent, KmsMessage, KmsOperation, OperationValue};
use events::HexVector;
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest, ProtoCoin};
use kms_blockchain_client::query_client::{
    ContractQuery, OperationQuery, QueryClient, QueryClientBuilder, QueryContractRequest,
};
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::util::key_setup::test_tools::{compute_cipher_from_storage, TypedPlaintext};
use simulator::conf::SimConfig;
use std::error::Error;
use std::path::Path;
use strum::IntoEnumIterator;

#[derive(Debug, Parser)]
struct Execute {
    #[clap(long, short = 'e')]
    to_encrypt: u8,
}

#[derive(Debug, Parser)]
struct Query {
    #[clap(long, short = 't')]
    txn_id: String,
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
    to_encrypt: u8,
    client: Client,
    query_client: QueryClient,
) -> Result<(), Box<dyn Error + 'static>> {
    let mut client = client;
    let key_id = "2add68b744d5f5dce2c365b2587a4374f60e4d98";
    let typed_to_encrypt = TypedPlaintext::U8(to_encrypt);
    let (cypher, _) =
        compute_cipher_from_storage(Some(Path::new("./keys")), typed_to_encrypt, key_id).await;
    let value = OperationValue::Decrypt(
        DecryptValues::builder()
            .ciphertext_handle(cypher.clone())
            .fhe_type(FheType::Euint8)
            .key_id(hex::decode(key_id).unwrap())
            .version(1)
            .randomness(vec![1, 2, 3, 4, 5])
            .build(),
    );

    let request = ExecuteContractRequest::builder()
        .message(
            KmsMessage::builder()
                .proof(vec![1, 2, 3])
                .value(value)
                .build(),
        )
        .gas_limit(3_100_000)
        .funds(vec![ProtoCoin::builder()
            .amount(20_000_000)
            .denom("ucosm".to_string())
            .build()])
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
    let ev = KmsEvent::builder()
        .operation(query.event)
        .txn_id(txn_id)
        .proof(vec![1, 2, 3])
        .build();
    let query_req = ContractQuery::GetOperationsValue(OperationQuery::builder().event(ev).build());

    let request = QueryContractRequest::builder()
        .contract_address(sim_config.contract)
        .query(query_req)
        .build();
    let value: Vec<OperationValue> = query_client.query_contract(request).await?;
    value.iter().for_each(|x| match x {
        OperationValue::DecryptResponse(decrypt) => {
            let payload: DecryptionResponsePayload = bincode::deserialize(
                <&HexVector as Into<Vec<u8>>>::into(decrypt.payload()).as_slice(),
            )
            .unwrap();
            let actual_pt: Plaintext = deserialize(&payload.plaintext).unwrap();
            tracing::info!("Decrypt Result: Plaintext Decrypted {:?} ", actual_pt);
        }
        _ => tracing::info!("Incorrect Response: {:?}", x),
    });

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + 'static>> {
    let config = Config::parse();
    let sim_conf: SimConfig = Settings::builder()
        .path(
            &config
                .file_conf
                .unwrap_or_else(|| "config/default.toml".to_string()),
        )
        .env_prefix("SIMULATOR")
        .build()
        .init_conf()?;
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
            execute_contract(ex.to_encrypt, client, query_client).await?
        }
        Command::QueryContract(q) => query_contract(sim_conf, q, query_client).await?,
    }

    Ok(())
}
