# Abrupt-interruption recovery

CodeProbe release publication uses a durable rollback journal in `.codeprobe-release-recovery/` beside the public packet. Before a public ZIP, checksum sidecar or package-audit sidecar is moved, its previous state is copied and fsynced and the pending operation is recorded atomically.

If publication is interrupted by process death, machine shutdown or power loss, the next publication attempt calls the recovery boundary before changing another packet member. The explicit recovery command is:

```bash
python3 -I -S -B tools/recover_release.py --output-dir /path/to/output
```

Recovery is conservative. A complete new generation is retained only when all three packet members exist and agree on the ZIP SHA-256. Otherwise every recorded target is restored to its pre-transaction state. Missing prior targets are removed. Corrupt or escaping journals fail closed and require operator investigation.

This protocol does not claim that three independent directory entries become one filesystem-atomic operation. It establishes deterministic rollback to a consistent preceding packet after an uncatchable interruption. Durability still depends on the host filesystem and storage stack honouring file and directory flushes.
