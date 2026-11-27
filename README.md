# migcheck
Read-only checks for VM migrations. Collects a baseline on the source VM, checks the migrated copy against it and flags only real differences: disks, network, services, ports, TLS, logs. Windows (PowerShell) and Linux (bash). Built for AVS to Azure, and can be adapted to other migrations.
