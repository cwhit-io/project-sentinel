# Recovery

Run `scripts/backup.sh` for encrypted, access-controlled PostgreSQL backups and `sentinel export` for a sanitized Zabbix configuration snapshot. Back up the OpenBao data and audit volumes separately with an approved encryption recipient, with recovery material held outside the backup location; never store unseal keys beside snapshots. Test restores with synthetic, non-production secrets only. A restore is not accepted until the isolated instance starts, TLS verifies, audit records are written, and a short-lived test identity can be revoked.

The protected operator sequence is: stop writes, create an encrypted archive of each named volume, verify the archive without decrypting into a shared location, record checksum and custody location, then restore into an isolated Compose project. Never put recovery shares, tokens, private keys, or decrypted archives in this repository.

For rollback, stop apply, preserve the plan and audit record, restore the last known-good export or reverse the reviewed plan, verify health, then regenerate the export. Component upgrades require a tested backup, pinned image change, health verification, and a documented rollback to the prior image and data backup.
