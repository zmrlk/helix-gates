# Backup and restore drill

ASSUMPTION: draft; never run against production or overwrite the source.
1. Record owner, dataset classification, backup retention/encryption and RPO/RTO: TODO
2. Identify an isolated empty restore destination and synthetic representative data: TODO
3. Record backup/restore commands, engine/version and timestamp: TODO
4. Restore; verify row counts, checksums, relations and application invariants: TODO
5. Measure recovered point and recovery duration against RPO/RTO: TODO
6. Record failed checks, cleanup, reviewer and dated evidence: TODO
Configuration is preparation; only an observed drill proves recovery.
