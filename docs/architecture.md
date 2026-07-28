# Architecture

Git is the desired-state and recovery layer. YAML inventory and policy files feed the controlled operator. The operator validates references, discovers active Zabbix state through a narrow API client, produces a deterministic plan, pauses for review, applies approved mutations, verifies, and writes a sanitized export. Zabbix Server and Web use PostgreSQL. Zabbix events reach StackStorm through an authenticated webhook; StackStorm is the only remediation executor. OpenBao holds all sensitive values and is accessed by reference.

The compose network is internal. Local ports bind to loopback only and a trusted-network or TLS reverse proxy must be placed in front of any shared access. OpenBao uses persistent storage and TLS configuration; initialization, unseal, audit setup, and recovery are protected operator procedures and are not automated.
