# DomainEthRouter

DomainEthRouter is a Windows tool that automatically configures the OpenAI routing table based on domain name to specify the network card interface for outbound traffic.

## Requirements

To use DomainEthRouter, you must have:

- A Windows machine with an Ethernet interface and a wireless interface.
- [Go](https://golang.org/doc/install) installed on your machine.
- A configuration file in the YAML format (see the next section).

## Configuration

The configuration file for DomainEthRouter is in the YAML format and must have the following structure:

```yaml
# Which domains traffic should be routed to the specified network interface card.
domains:
  - ipecho.io # to check if the routing is successful
  - chat.openai.com
  - auth0.openai.com
  - pay.openai.com

# Specify which network interface card to use as the network gateway.
network_interface: "WLAN"
```

The domains field is a list of domains for which the tool will configure the routing table. The network_interface field specifies the network interface card to use as the network gateway.

## Installation

To install DomainEthRouter, follow these steps:

Clone this repository to your local machine.
Navigate to the root directory of the repository.
Run make to compile the program.
Run the DomainEthRouter executable file to start the program.

## Usage

To use DomainEthRouter, simply run the DomainEthRouter executable file. The tool will automatically configure the routing table based on the domains specified in the configuration file.

## License

This tool is licensed under the [MIT License](LICENSE).