package amtool

import "testing"

func TestDefaultOptions(t *testing.T) {
	options := NewOptions()
	if options.Namespace != "monitoring" {
		t.Fatalf("Namespace = %q, want monitoring", options.Namespace)
	}
	if options.StatefulSet != "alertmanager-main" {
		t.Fatalf("StatefulSet = %q, want alertmanager-main", options.StatefulSet)
	}
	if options.Container != "alertmanager" {
		t.Fatalf("Container = %q, want alertmanager", options.Container)
	}
	if options.AlertmanagerURL != "http://localhost:9093" {
		t.Fatalf("AlertmanagerURL = %q, want http://localhost:9093", options.AlertmanagerURL)
	}
}
