## jit decoys expect

Mark a program's decoy reads as expected

### Synopsis

Mark PROGRAM's decoy reads as expected: of one protected file with --file, else of every one. PROGRAM is the reader's executable as `jit audit` names it.

```
jit decoys expect PROGRAM [flags]
```

### Examples

```
  jit decoys expect /Applications/Editor.app/Contents/MacOS/Editor --file ~/work/app/.env
```

### Options

```
      --file string     the protected file the mark covers (default: every protected file)
      --format string   output format: "text" (default) or "json" (default "text")
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit decoys](jit_decoys.md)	 - Say which programs are expected to read protected files

