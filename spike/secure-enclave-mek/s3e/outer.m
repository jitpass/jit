// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

// Stand-in for JitPass (the outer app's main executable). S3e never runs it;
// it exists so the outer bundle is a real, signable app.
#include <stdio.h>
int main(void) { puts("outer app stand-in"); return 0; }
