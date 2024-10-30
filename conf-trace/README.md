# Conf-trace

Conf-trace is a library shared by the multiple kms services that does the configuration of the `tracing` library.

All grpc requests between services should use `make_request` from this library to porperly propagate the request-id between services.
