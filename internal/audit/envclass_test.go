// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"strings"
	"testing"
)

// Built at run time so the repo's leak guard does not read a fixture as a
// committed credential. Invented values.
var (
	fixtureMixed = strings.Join([]string{"Qx7vK2", "mP9wLs", "4Rt8Yn", "3Bz6Hc"}, "")
	fixtureHex   = strings.Repeat("a3f9c2e8", 4)
)

// Fixture values are invented and shaped only as far as each rule needs.
func TestClassifyEnvVar(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		want       EnvVarClass
	}{
		// Settings: what a .env holds beside its credentials.
		{"BILLING_URL", "https://billing.example.com", EnvVarSetting},
		{"BILLING_CLIENT_ID", "sync-reporter", EnvVarSetting},
		{"BILLING_CLIENT_ID", "3f2b8c1e-9a4d-4e7b-8c2a-1d5e6f7a8b9c", EnvVarSetting},
		{"KEEP_REPORTS", "30", EnvVarSetting},
		{"PORT", "3000", EnvVarSetting},
		{"DEBUG", "true", EnvVarSetting},
		{"REPORT_DIR", "~/reports", EnvVarSetting},
		{"EMPTY", "", EnvVarSetting},
		// A reference holds nothing at rest.
		{"TOKEN", "${GH_TOKEN}", EnvVarSetting},

		// Secrets: a random-looking value under a secret name, a random value
		// under any name, a long hex key.
		{"BILLING_CLIENT_SECRET", fixtureMixed, EnvVarSecret},
		{"OTHER", "Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7", EnvVarSecret},
		{"API_KEY", fixtureHex, EnvVarSecret},
		// A 1Password reference keeps going where it always went: the vault
		// links it as op://.
		{"API_KEY", "op://Work/Billing/credential", EnvVarSecret},

		// Check: the name says secret, the value does not look like one. A
		// short password is exactly this shape, which is why Check goes to
		// the vault by default.
		{"OUTPUT_FILE_DEV_SECRETS", "dev_secrets.json", EnvVarCheck},
		{"DB_PASSWORD", "hunter2", EnvVarCheck},
	} {
		if got := ClassifyEnvVar(tc.key, tc.value); got != tc.want {
			t.Errorf("ClassifyEnvVar(%s=%q) = %s, want %s", tc.key, tc.value, got, tc.want)
		}
	}
}

// The file scanner claims only the FIRST random-looking value in a file: one
// is enough to raise its finding. The split must judge every line alone, or
// the second such value stays in plain text.
func TestClassifyEnvVarJudgesEachValueAlone(t *testing.T) {
	for _, v := range []string{"Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7", "Zq4Wx8Ev2Rc6Tb1Yn5Um9Ik3"} {
		if got := ClassifyEnvVar("SERVICE_VALUE", v); got != EnvVarSecret {
			t.Errorf("ClassifyEnvVar(SERVICE_VALUE=%q) = %s, want secret", v, got)
		}
	}
}

func TestEnvVarClassInVault(t *testing.T) {
	if !EnvVarSecret.InVault() || !EnvVarCheck.InVault() || EnvVarSetting.InVault() {
		t.Error("InVault: secret and check go to the vault, setting does not")
	}
}
