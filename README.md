# Tor Controller Library in Rust
Provides a library to communicate with the Tor control socket to generate ephemeral onion services.
Integrates an async event handler running in a separate task which is handling control events.

## Features
 - [x] Async event handler
 - [x] Creating v3 onion services
 - [x] Creating secret keys for onion services
 - [x] Delete an onion service
 - [x] Register for events
 - [x] Sending raw commands
 - [x] Generating public keys from secret keys
 - [x] Generating onion address from public keys

## Documentation
The current state is well documented in the code.
With the command `cargo doc --open` you can create and open the documentation.
Some of the functions do have an example on how to use it.

## Examples
There are also simple examples to show how to use the library under the directory `examples`.
Use `cargo r --example <name>` to run one of them.

## Acknowledgements

This work has been carried out within the scope of Digidow, the Christian Doppler Laboratory for Private Digital Authentication in the Physical World. We gratefully acknowledge financial support by the Austrian Federal Ministry of Labour and Economy, the National Foundation for Research, Technology and Development, the Christian Doppler Research Association, 3 Banken IT GmbH, ekey biometric systems GmbH, Kepler Universitätsklinikum GmbH, NXP Semiconductors Austria GmbH & Co KG, and Österreichische Staatsdruckerei GmbH.

## LICENSE

Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.

**License**: [European Union Public License v1.2](https://joinup.ec.europa.eu/software/page/eupl)
