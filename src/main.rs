use distributed_decryption::execution::execute_bitdec_circuit;
use distributed_decryption::parser::*;
use distributed_decryption::shamir::ShamirSharing;

fn main() -> Result<(), anyhow::Error> {
    let circuit = Circuit::try_from(BIT_DEC_CIRCUIT)?;
    let x = 10;
    let shared_x = ShamirSharing { share: x };
    let v = execute_bitdec_circuit(shared_x, circuit.clone())?;
    println!("bit_dec = {v:?}");
    Ok(())
}
