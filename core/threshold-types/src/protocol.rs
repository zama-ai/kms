/// Provide a short description of a protocol, indented with `depth` number of spaces
pub trait ProtocolDescription {
    const INDENT_STRING: &str = "   ";
    fn protocol_desc(depth: usize) -> String;
}
