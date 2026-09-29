// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

#include <stdint.h>

typedef struct {
    int ok;
    long code;       // LAError code, or the CFError code on the enclave path
    char *domain;    // error domain, NULL on success
    char *msg;       // error text, NULL on success
    int64_t start_ns; // just before the call that raises the dialog
    int64_t end_ns;   // when that call returned
} PromptResult;

int64_t spike_now_ns(void);

// prompt_keychain raises the dialog the way keychainwrap does today:
// LAContext evaluatePolicy(DeviceOwnerAuthentication).
PromptResult prompt_keychain(const char *reason);

// prompt_enclave raises it the way secureenclave does: a decrypt with a
// Secure Enclave key that requires user presence. The key is EPHEMERAL
// (never stored), made fresh for this one prompt.
PromptResult prompt_enclave(const char *reason);

// cancel_prompt invalidates the LAContext of the prompt in flight, from
// any thread. A cancel that arrives before the prompt starts is kept and
// applied the moment it does.
void cancel_prompt(void);
