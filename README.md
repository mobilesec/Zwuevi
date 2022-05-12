# Zwuevi
Provides a library to communicate with the TOR control socket.
Integrates an async event handler running in a separate task.

## Features
 - [x] Async event handler
 - [x] Creating v3 onion services
 - [x] Creating secret keys for onion services
 - [x] Delete an onion service
 - [x] Register for events
 - [x] Sending raw commands
 - [x] Generating public keys from secret keys
 - [x] Generating onion address from public keys
 - [ ] Rescheduling onion services

## Documentation
The current state is well documented in the code.
With the command `cargo doc --open` you can create and open it.
Some of the functions do have an example on how to call them.

## Examples
There are also simple examples to show how to use the library under the directory `examples`.
Use `cargo r --example <name>` to run one of them.
