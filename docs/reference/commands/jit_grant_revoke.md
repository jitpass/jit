## jit grant revoke

End a process grant now

### Synopsis

End a grant immediately. No authentication: reducing access is always
free, and the kill switch is deliberately the easiest command in the
feature. The ending is recorded in 'jit audit'.

For a grant made with --until-revoked this is the only way it ends, and it
deletes the key that grant holds, so the secrets it covered go back to
asking for Touch ID.

```
jit grant revoke ID
```

### Options inherited from parent commands

```
      --quiet   suppress the progress spinner/status trail (results still print)
```

### SEE ALSO

* [jit grant](jit_grant.md)	 - Pre-approve a program to use profiles unattended

