package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/svinson1121/vectorcore-hss/internal/models"
)

type idrRecorder struct {
	mu    sync.Mutex
	imsis []string
}

func (r *idrRecorder) SendIDRByIMSI(_ context.Context, imsi string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.imsis = append(r.imsis, imsi)
	return nil
}

func (r *idrRecorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.imsis...)
}

func TestUpdateSubscriberSendsIDROnAccessRestrictionChange(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	idr := &idrRecorder{}
	s.WithIDR(idr)

	enabled := true
	oldARD := uint32(64)
	newARD := uint32(320)
	sub := models.Subscriber{
		IMSI:                  "001010000000101",
		Enabled:               &enabled,
		AUCID:                 1,
		DefaultAPN:            1,
		APNList:               "1",
		AccessRestrictionData: &oldARD,
	}
	mustCreate(t, s.db, &sub)

	updated := sub
	updated.AccessRestrictionData = &newARD
	if _, err := s.updateSubscriber(ctx, &SubscriberUpdateInput{ID: sub.SubscriberID, Body: &updated}); err != nil {
		t.Fatalf("update subscriber: %v", err)
	}

	// The IDR fires in a goroutine; poll briefly to let it run.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		if got := idr.get(); len(got) == 1 && got[0] == sub.IMSI {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("IDR calls = %#v, want [%q]", idr.get(), sub.IMSI)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUpdateSubscriberSkipsIDRWhenAccessRestrictionUnchanged(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	idr := &idrRecorder{}
	s.WithIDR(idr)

	enabled := true
	ard := uint32(64)
	sub := models.Subscriber{
		IMSI:                  "001010000000102",
		Enabled:               &enabled,
		AUCID:                 1,
		DefaultAPN:            1,
		APNList:               "1",
		AccessRestrictionData: &ard,
	}
	mustCreate(t, s.db, &sub)

	updated := sub
	if _, err := s.updateSubscriber(ctx, &SubscriberUpdateInput{ID: sub.SubscriberID, Body: &updated}); err != nil {
		t.Fatalf("update subscriber: %v", err)
	}

	if got := idr.get(); len(got) != 0 {
		t.Fatalf("unexpected IDR calls: %#v", got)
	}
}

func TestUpdateSubscriberSkipsIDRWhenDisabled(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()

	idr := &idrRecorder{}
	s.WithIDR(idr)

	enabled := true
	oldARD := uint32(64)
	newARD := uint32(320)
	sub := models.Subscriber{
		IMSI:                  "001010000000103",
		Enabled:               &enabled,
		AUCID:                 1,
		DefaultAPN:            1,
		APNList:               "1",
		AccessRestrictionData: &oldARD,
	}
	mustCreate(t, s.db, &sub)

	disabled := false
	updated := sub
	updated.Enabled = &disabled
	updated.AccessRestrictionData = &newARD
	if _, err := s.updateSubscriber(ctx, &SubscriberUpdateInput{ID: sub.SubscriberID, Body: &updated}); err != nil {
		t.Fatalf("update subscriber: %v", err)
	}

	if got := idr.get(); len(got) != 0 {
		t.Fatalf("unexpected IDR calls: %#v", got)
	}
}
