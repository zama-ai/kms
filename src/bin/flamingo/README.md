# Flamin workers

Flamin workers use gRPC choreography, and gRPC networking.

Note that for security reasons flamin workers will refuse re-running a session with same id more than once.

## Example

To run the four party example in `/examples/test.flamin` open up 4 terminals and type the following:


```sh

flamin \
    --identity localhost:50000
    --port 50000

flamin \
    --identity localhost:50001
    --port 50001

flamin \
    --identity localhost:50002
    --port 50002

flamin \
    --identity localhost:50003
    --port 50003

```

and then launch a session from the root directory using the following:

```sh
flamingo --session-id 1 ./examples/test.session
```

To see tracing outputs, add `RUST_LOG=info` or `RUST_LOG=debug` in front of the running command.