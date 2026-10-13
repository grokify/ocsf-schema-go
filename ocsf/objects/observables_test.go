package objects_test

import (
	"testing"

	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// TestObservableRegistries spot-checks generated observable type_id maps
// against published OCSF observable values.
func TestObservableRegistries(t *testing.T) {
	if got := objects.ObservableTypeIDByDictionaryType["ip_t"]; got != 2 {
		t.Errorf("ObservableTypeIDByDictionaryType[ip_t] = %d, want 2 (IP Address)", got)
	}
	if got := objects.ObservableTypeIDByObject["fingerprint"]; got != 30 {
		t.Errorf("ObservableTypeIDByObject[fingerprint] = %d, want 30", got)
	}
	// Extension object observables are included (win extension reg_key).
	if got := objects.ObservableTypeIDByObject["reg_key"]; got != 28 {
		t.Errorf("ObservableTypeIDByObject[reg_key] = %d, want 28", got)
	}
	if len(objects.ObservableTypeIDByAttribute) == 0 {
		t.Error("ObservableTypeIDByAttribute is empty")
	}
	// Captions for observable type ids come from the Observable object enum.
	if got := objects.ObservableTypeIDCaptions[2]; got != "IP Address" {
		t.Errorf("ObservableTypeIDCaptions[2] = %q, want IP Address", got)
	}
}
