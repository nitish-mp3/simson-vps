package calls

import "testing"

func TestStaleRingSnapshotCannotExpireANewlyAnsweredCallback(t *testing.T) {
	manager := NewManager()
	manager.Create(&Call{ID: "one", FromNode: "sip:3101", ToNode: "sip:9123"})
	snapshot := manager.Snapshots()[0]
	manager.Accept("one", "")
	if _, ended := manager.EndIfState("one", snapshot.State, "timeout"); ended {
		t.Fatal("a stale ringing observation ended an answered call")
	}
	if manager.Get("one").State != StateActive {
		t.Fatal("healthy callback state changed")
	}
}
