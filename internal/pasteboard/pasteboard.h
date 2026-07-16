#ifndef PASTEBOARD_H
#define PASTEBOARD_H

// pb_write_concealed puts len bytes of UTF-8 text on the general
// pasteboard, declaring org.nspasteboard.ConcealedType alongside it — the
// de-facto convention (nspasteboard.org) well-behaved clipboard managers
// honor by NOT recording the entry in their history. Returns the
// pasteboard's changeCount after the write (the handle pb_clear_if_unchanged
// keys on), or -1 if the bytes aren't valid UTF-8.
long pb_write_concealed(const char *bytes, int len);

// pb_change_count returns the general pasteboard's current changeCount —
// for a caller that filled the pasteboard some other way (pbcopy) and
// still wants the clear-if-unchanged contract.
long pb_change_count(void);

// pb_clear_if_unchanged clears the general pasteboard if and only if its
// changeCount still equals change_count — i.e. nothing has been copied
// since the write that returned it, so what's being cleared is still our
// secret and never something the user copied afterwards. Returns 1 if it
// cleared, 0 if the pasteboard had moved on. Comparing counts, not
// contents, means the secret's value is never re-read or carried around
// to do the clear.
int pb_clear_if_unchanged(long change_count);

#endif
