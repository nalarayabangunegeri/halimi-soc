package ingest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/incidents"
)

type fakePublisher struct {
	alerts    []*alerts.Alert
	incidents []*incidents.Incident
}

func (f *fakePublisher) PublishAlertCreated(a *alerts.Alert) { f.alerts = append(f.alerts, a) }
func (f *fakePublisher) PublishIncident(_ bool, inc *incidents.Incident) {
	f.incidents = append(f.incidents, inc)
}

func TestIngesterDefaults(t *testing.T) {
	ing, _, _, _ := build(t)
	// The fixture builds with maxBatch 100; a non-positive bound must fall
	// back to the documented default rather than meaning "unbounded".
	def := ingest.New(nil, nil, nil, validation.DefaultOptions(), nil, 0)
	if def.MaxBatch() != 1000 {
		t.Fatalf("default MaxBatch = %d, want 1000", def.MaxBatch())
	}
	if ing.MaxBatch() != 100 {
		t.Fatalf("MaxBatch = %d, want 100", ing.MaxBatch())
	}
}

func TestIngestRejectsOversizedBatch(t *testing.T) {
	ing, _, _, now := build(t)
	var batch []*model.Event
	for i := 0; i < 101; i++ {
		batch = append(batch, sshFailure("evt_big", "203.0.113.7", *now))
	}
	if _, err := ing.Ingest(context.Background(), batch); !errors.Is(err, ingest.ErrBatchTooLarge) {
		t.Fatalf("err = %v, want ErrBatchTooLarge", err)
	}
}

func TestIngestPublishesAlertsAndIncidents(t *testing.T) {
	ing, _, _, now := build(t)
	pub := &fakePublisher{}
	ing.SetPublisher(pub)

	base := *now
	var batch []*model.Event
	for i := 0; i < 3; i++ {
		batch = append(batch, sshFailure(id.NewEvent(), "203.0.113.7", base))
	}
	res, err := ing.Ingest(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Alerts) == 0 {
		t.Fatal("expected detection to produce an alert")
	}
	if len(pub.alerts) != len(res.Alerts) {
		t.Fatalf("published alerts = %d, want %d", len(pub.alerts), len(res.Alerts))
	}
	if len(pub.incidents) == 0 {
		t.Fatal("expected correlation to publish an incident")
	}
}

func TestIngestNilEventIsRejectedIndividually(t *testing.T) {
	ing, _, _, now := build(t)
	// A nil entry must be rejected with an empty id, not panic the batch, and
	// the valid sibling must still be ingested.
	res, err := ing.Ingest(context.Background(), []*model.Event{
		nil,
		sshFailure(id.NewEvent(), "203.0.113.7", *now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].ID != "" {
		t.Fatalf("rejected = %+v, want one rejection with an empty id", res.Rejected)
	}
	if res.Inserted != 1 {
		t.Fatalf("inserted = %d, want 1", res.Inserted)
	}
}
