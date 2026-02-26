// TODO(dp): document/describe this

pub trait ProtocolDescription {
    const INDENT_STRING: &str = "   ";
    fn protocol_desc(depth: usize) -> String;
}
