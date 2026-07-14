// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

//go:build darwin

package cli

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildK8sExecCredentialOutputTokenShape(t *testing.T) {
	out, err := buildK8sExecCredentialOutput(map[string]string{"TOKEN": "sk_test_token"})
	if err != nil {
		t.Fatalf("buildK8sExecCredentialOutput: %v", err)
	}
	if out.APIVersion != "client.authentication.k8s.io/v1" {
		t.Errorf("APIVersion = %q, want client.authentication.k8s.io/v1", out.APIVersion)
	}
	if out.Kind != "ExecCredential" {
		t.Errorf("Kind = %q, want ExecCredential", out.Kind)
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `"token":"sk_test_token"`) {
		t.Errorf("expected token in output, got: %s", got)
	}
	if strings.Contains(got, "clientCertificateData") || strings.Contains(got, "clientKeyData") {
		t.Errorf("expected cert fields omitted for a token-only profile (omitempty), got: %s", got)
	}
}

func TestBuildK8sExecCredentialOutputClientCertShape(t *testing.T) {
	// The vault holds the kubeconfig value verbatim: base64-encoded PEM.
	// Y2VydA==/a2V5 are base64 of "cert"/"key" — stand-ins for real PEM
	// blocks. The ExecCredential must carry the DECODED bytes, since
	// client-go wants PEM directly there, never the base64 (feeding it
	// base64 is what broke kubectl with "failed to find any PEM data").
	out, err := buildK8sExecCredentialOutput(map[string]string{
		"CLIENT_CERTIFICATE_DATA": "Y2VydA==",
		"CLIENT_KEY_DATA":         "a2V5",
	})
	if err != nil {
		t.Fatalf("buildK8sExecCredentialOutput: %v", err)
	}
	data, _ := json.Marshal(out)
	got := string(data)
	if !strings.Contains(got, `"clientCertificateData":"cert"`) || !strings.Contains(got, `"clientKeyData":"key"`) {
		t.Errorf("expected both cert fields decoded from base64 in output, got: %s", got)
	}
	if strings.Contains(got, "Y2VydA==") || strings.Contains(got, "a2V5") {
		t.Errorf("cert/key data should be base64-DECODED to PEM, not passed through as base64, got: %s", got)
	}
	if strings.Contains(got, `"token"`) {
		t.Errorf("expected token omitted for a cert-only profile (omitempty), got: %s", got)
	}
}

func TestBuildK8sExecCredentialOutputDecodesRealPEM(t *testing.T) {
	// A realistic single-line base64 of a PEM block round-trips to PEM.
	pem := "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(pem))
	out, err := buildK8sExecCredentialOutput(map[string]string{
		"CLIENT_CERTIFICATE_DATA": b64,
		"CLIENT_KEY_DATA":         b64,
	})
	if err != nil {
		t.Fatalf("buildK8sExecCredentialOutput: %v", err)
	}
	if out.Status.ClientCertificateData != pem {
		t.Errorf("ClientCertificateData = %q, want decoded PEM %q", out.Status.ClientCertificateData, pem)
	}
}

func TestPemFromKubeconfigDataPassesThroughNonBase64(t *testing.T) {
	// A value that's already PEM (not valid standard base64 — '-' isn't in
	// the alphabet) is passed through unchanged rather than mangled.
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
	if got := pemFromKubeconfigData(pem); got != pem {
		t.Errorf("pemFromKubeconfigData(alreadyPEM) = %q, want it unchanged", got)
	}
	if got := pemFromKubeconfigData(""); got != "" {
		t.Errorf("pemFromKubeconfigData(\"\") = %q, want empty", got)
	}
}

func TestBuildK8sExecCredentialOutputMissingCredentialsErrors(t *testing.T) {
	if _, err := buildK8sExecCredentialOutput(map[string]string{}); err == nil {
		t.Fatal("expected an error for a profile with no token or cert pair")
	}
	if _, err := buildK8sExecCredentialOutput(map[string]string{"CLIENT_CERTIFICATE_DATA": "Y2VydA=="}); err == nil {
		t.Fatal("expected an error for an incomplete cert/key pair")
	}
}
