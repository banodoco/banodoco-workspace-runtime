# Runtime agent rules

- Create a persistent backup only when the user explicitly requests one. The
  `runtime_protocol backup` command is the supported durable backup operation.
- Do not copy a realm database, CAS, support root, or runtime tree before routine
  startup, reconnect, upgrade, repair, migration, or replacement work. Do not
  nest backup directories or leave just-in-case copies in the checkout, `.otto`,
  temporary workspaces, or sibling paths.
- Runtime transactions may create same-filesystem temporary staging needed for
  atomic publication or rollback. Remove it after success or successful
  rollback. If rollback fails and a recovery copy must remain to protect data,
  report its exact path and recovery state; never silently retain it.
- When a user explicitly asks to retain a backup, use the verified backup API
  and a destination they specify. Do not infer backup intent from a migration,
  repair, or replacement request.
- Preserve failed replacement recovery roots until rollback is verified. On a
  successful replacement, remove the superseded realm unless the user opted in
  to retention.
