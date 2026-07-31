#ifndef PASTEBOARD_H
#define PASTEBOARD_H

// Each function below takes the pasteboard to act on by name. A NULL or empty
// name means NSPasteboard's general pasteboard, which is what every production
// caller passes and the only one that is a real clipboard.
//
// The name exists for the package's own test, for the same reason
// internal/screenlock's watch() takes its notification name rather than
// hard-coding the OS-owned one: driving the general pasteboard from a test
// would clear whatever the person running the suite had just copied, and
// pb_clear_if_unchanged would then be deleting their data rather than jit's
// secret. A named pasteboard is a private scratch board with identical
// changeCount semantics and no connection to the clipboard.

// pb_write_concealed puts len bytes of UTF-8 text on the pasteboard,
// declaring org.nspasteboard.ConcealedType alongside it — the de-facto
// convention (nspasteboard.org) well-behaved clipboard managers honor by NOT
// recording the entry in their history. Returns the pasteboard's changeCount
// after the write (the handle pb_clear_if_unchanged keys on), or -1 if the
// bytes aren't valid UTF-8.
long pb_write_concealed(const char *name, const char *bytes, int len);

// pb_change_count returns the pasteboard's current changeCount — for a
// caller that filled it some other way (pbcopy) and still wants the
// clear-if-unchanged contract.
long pb_change_count(const char *name);

// pb_clear_if_unchanged clears the pasteboard if and only if its changeCount
// still equals change_count — i.e. nothing has been copied since the write
// that returned it, so what's being cleared is still our secret and never
// something the user copied afterwards. Returns 1 if it cleared, 0 if the
// pasteboard had moved on. Comparing counts, not contents, means the secret's
// value is never re-read or carried around to do the clear.
int pb_clear_if_unchanged(const char *name, long change_count);

// pb_has_type reports whether the pasteboard currently declares type.
// TEST-ONLY: it exists so the package test can assert that
// org.nspasteboard.ConcealedType really is declared, which is the whole
// mechanism keeping a copied secret out of every clipboard manager's history
// — and a mechanism that fails completely silently if a refactor drops it.
// It reports type PRESENCE only and never reads a pasteboard's contents.
int pb_has_type(const char *name, const char *type);

#endif
