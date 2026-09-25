// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#ifndef SEK_H
#define SEK_H
// S3a's three operations, callable from Go. Each prints its own OK/FAIL line
// and returns 0 on success.
int sek_create(void);
int sek_find(void);
int sek_delete(void);
#endif
