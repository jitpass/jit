## jit mount

Re-point or register a project's live mounts

### Synopsis

Repairs the machine-local mount registry when a project has moved or
arrived by copy. jit records where a project's mounted files are using
absolute paths; renaming, moving or duplicating a folder leaves that
record pointing at the wrong place, and nothing reconciles it on its own.

Both subcommands edit the registry and nothing else — no secret is read
or written, so neither needs Touch ID.

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit mount record](jit_mount_record.md)	 - Write the project record for mounts already registered
* [jit mount register](jit_mount_register.md)	 - Serve a project's mounts on this Mac
* [jit mount relocate](jit_mount_relocate.md)	 - Re-point a mount registration at the project's new location

