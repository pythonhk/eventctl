package main

import "testing"

func TestDoctorRunsOfflineProtocolAndCryptoSelfTests(t *testing.T) {
	value, err := runDoctor(nil)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(doctorResult)
	if !ok {
		t.Fatalf("runDoctor() result type = %T", value)
	}
	if result.Status != "healthy" || !result.ParticipantSupported || result.ProtocolVersion != 1 || len(result.Cryptography) != 4 {
		t.Fatalf("runDoctor() = %#v", result)
	}
}

func TestDoctorRejectsPositionalInput(t *testing.T) {
	if _, err := runDoctor([]string{"unexpected"}); err == nil {
		t.Fatal("runDoctor() accepted positional input")
	}
}
