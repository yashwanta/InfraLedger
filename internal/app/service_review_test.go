package app

import (
	"strings"
	"testing"
)

func TestReviewExplainsEvidenceWithoutTrustingProcessName(t *testing.T) {
	review := serviceReview("lsass.exe", 443, "127.0.0.1")
	if S(review, "reviewStatus") != "Identity unverified" || !strings.Contains(S(review, "description"), "authentication") {
		t.Fatal(review)
	}
	review = serviceReview("Process 555", 23, "0.0.0.0")
	if S(review, "reviewStatus") != "Needs review" || len(review["reviewReasons"].([]string)) != 3 {
		t.Fatal(review)
	}
}

func TestLegacyProcessMigrationPreservesIDsAndManualApplications(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct{ id, key, collector string }{{"process", "app:1:lsass.exe", "collector"}, {"listener", "service:device:443", "collector"}, {"manual", "", ""}} {
		a.run("INSERT INTO records(id,type,data,created,updated) VALUES(?,'applications',?,'now','now')", record.id, J(M{"name": record.id, "sourceKey": record.key, "collectorId": record.collector}))
	}
	a.Close()
	a, err = New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if S(a.get("SELECT type FROM records WHERE id='process'"), "type") != "services" || S(a.get("SELECT type FROM records WHERE id='listener'"), "type") != "services" || S(a.get("SELECT type FROM records WHERE id='manual'"), "type") != "applications" {
		t.Fatal("incorrect migration")
	}
}
