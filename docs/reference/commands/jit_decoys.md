## jit decoys

Say which programs are expected to read protected files

### Synopsis

A protected file serves decoys to any program without a grant, and every read is logged. Some readers are routine, such as an editor indexing a folder or a backup tool. Marking one expected tags its decoy reads `expected` in `jit audit`, so JitPass counts them apart and does not warn about them. It still gets decoys and still needs a grant for a real value: this changes what is said, not what is served.

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit](jit.md)	 - Local-first developer secret runtime
* [jit decoys expect](jit_decoys_expect.md)	 - Mark a program's decoy reads as expected
* [jit decoys expected](jit_decoys_expected.md)	 - List the programs whose decoy reads are expected
* [jit decoys unexpect](jit_decoys_unexpect.md)	 - Remove a program's expected mark

