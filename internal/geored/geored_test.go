package geored

// geored_test.go — httptest-based integration tests for the geored package.
//
// Coverage:
//   - bearerAuth middleware: valid token, missing header, wrong token
//   - eventsHandler: valid batch, loop-prevention, malformed JSON, wrong HTTP method
//   - OAM event apply: subscriber_put calls UpsertSubscriber,
//     subscriber_del calls DeleteSubscriberByIMSI
//   - snapshotHandler: returns JSON snapshot, rejects non-GET
//   - healthHandler: always 200 with JSON body
//   - Round-trip: standard http.Client posts a well-formed batch to an
//     httptest.NewServer wrapping the same mux

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/svinson1121/vectorcore-hss/internal/models"
	"github.com/svinson1121/vectorcore-hss/internal/repository"
)

func noopLogger() *zap.Logger { return zap.NewNop() }

// ── stub repository ───────────────────────────────────────────────────────────

// stubRepo satisfies repository.Repository with no-ops or zero returns.
// It records calls that the geored handlers are expected to make.
type stubRepo struct {
	mu sync.Mutex

	upsertSubscriberCalls []models.Subscriber
	deleteSubscriberIMSIs []string
	upsertAUCCalls        []models.AUC
	deleteAUCIDs          []int
}

func (r *stubRepo) recordUpsertSubscriber(s models.Subscriber) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upsertSubscriberCalls = append(r.upsertSubscriberCalls, s)
}

func (r *stubRepo) recordDeleteSubscriber(imsi string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteSubscriberIMSIs = append(r.deleteSubscriberIMSIs, imsi)
}

// --- Repository interface ---------------------------------------------------

func (r *stubRepo) GetAUCByIMSI(_ context.Context, _ string) (*models.AUC, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetAUCByID(_ context.Context, id int) (*models.AUC, error) {
	return &models.AUC{AUCID: id, SQN: 0}, nil
}
func (r *stubRepo) AtomicGetAndIncrementSQN(_ context.Context, _ int, _ int64) (*models.AUC, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) ResyncSQN(_ context.Context, _ int, _ int64) error { return nil }
func (r *stubRepo) GetAlgorithmProfile(_ context.Context, _ int64) (*models.AlgorithmProfile, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetAPNByID(_ context.Context, _ int) (*models.APN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetSubscriberByIMSI(_ context.Context, _ string) (*models.Subscriber, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetSubscriberByMSISDN(_ context.Context, _ string) (*models.Subscriber, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) UpdateServingMME(_ context.Context, _ string, _ *repository.ServingMMEUpdate) error {
	return nil
}
func (r *stubRepo) UpdateServingSGSN(_ context.Context, _ string, _ *repository.ServingSGSNUpdate) error {
	return nil
}
func (r *stubRepo) UpdateServingVLR(_ context.Context, _ string, _ *repository.ServingVLRUpdate) error {
	return nil
}
func (r *stubRepo) UpdateServingMSC(_ context.Context, _ string, _ *repository.ServingMSCUpdate) error {
	return nil
}
func (r *stubRepo) UpdateServingAMF(_ context.Context, _ string, _ *repository.ServingAMFUpdate) error {
	return nil
}
func (r *stubRepo) UpsertServingPDUSession(_ context.Context, _ *models.ServingPDUSession) error {
	return nil
}
func (r *stubRepo) DeleteServingPDUSession(_ context.Context, _ string, _ int) error { return nil }
func (r *stubRepo) ListServingPDUSessions(_ context.Context, _ string) ([]models.ServingPDUSession, error) {
	return nil, nil
}
func (r *stubRepo) GetIMSSubscriberByMSISDN(_ context.Context, _ string) (*models.IMSSubscriber, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetIMSSubscriberByIMSI(_ context.Context, _ string) (*models.IMSSubscriber, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) UpdateIMSSCSCF(_ context.Context, _ string, _ *repository.IMSSCSCFUpdate) error {
	return nil
}
func (r *stubRepo) UpdateIMSPCSCF(_ context.Context, _ string, _ *repository.IMSPCSCFUpdate) error {
	return nil
}
func (r *stubRepo) GetIFCProfileByID(_ context.Context, _ int) (*models.IFCProfile, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetAPNByName(_ context.Context, _ string) (*models.APN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetAllChargingRules(_ context.Context) ([]models.ChargingRule, error) {
	return nil, nil
}
func (r *stubRepo) GetChargingRulesByNames(_ context.Context, _ []string) ([]models.ChargingRule, error) {
	return nil, nil
}
func (r *stubRepo) GetChargingRulesByIDs(_ context.Context, _ []int) ([]models.ChargingRule, error) {
	return nil, nil
}
func (r *stubRepo) GetTFTsByGroupID(_ context.Context, _ int) ([]models.TFT, error) { return nil, nil }
func (r *stubRepo) UpsertServingAPN(_ context.Context, _ *models.ServingAPN) error  { return nil }
func (r *stubRepo) DeleteServingAPNBySession(_ context.Context, _ string) error     { return nil }
func (r *stubRepo) GetServingAPNBySession(_ context.Context, _ string) (*models.ServingAPN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetServingAPNByIMSI(_ context.Context, _ string) (*models.ServingAPN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetServingAPNByMSISDN(_ context.Context, _ string) (*models.ServingAPN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetServingAPNByIdentity(_ context.Context, _ string) (*models.ServingAPN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetServingAPNByUEIP(_ context.Context, _ string) (*models.ServingAPN, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetSubscriberRoutingBySubscriberAndAPN(_ context.Context, _, _ int) (*models.SubscriberRouting, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) GetRoamingRuleByMCCMNC(_ context.Context, _, _ string) (*models.RoamingRules, error) {
	return nil, repository.ErrNotFound
}
func (r *stubRepo) UpsertEmergencySubscriber(_ context.Context, _ *models.EmergencySubscriber) error {
	return nil
}
func (r *stubRepo) DeleteEmergencySubscriberByIMSI(_ context.Context, _ string) error { return nil }
func (r *stubRepo) ListEIR(_ context.Context, _ *[]models.EIR) error                  { return nil }
func (r *stubRepo) EIRNoMatchResponse() int                                            { return 0 }
func (r *stubRepo) UpsertIMSIIMEIHistory(_ context.Context, _, _, _, _ string, _ int) error {
	return nil
}
func (r *stubRepo) StoreMWD(_ context.Context, _ *models.MessageWaitingData) error { return nil }
func (r *stubRepo) GetMWDForIMSI(_ context.Context, _ string) ([]models.MessageWaitingData, error) {
	return nil, nil
}
func (r *stubRepo) DeleteMWD(_ context.Context, _, _ string) error { return nil }
func (r *stubRepo) InvalidateCache(_ string)                        {}

func (r *stubRepo) ListAllAUC(_ context.Context) ([]models.AUC, error) { return nil, nil }
func (r *stubRepo) ListAllSubscribers(_ context.Context) ([]models.Subscriber, error) {
	return nil, nil
}
func (r *stubRepo) ListAllIMSSubscribers(_ context.Context) ([]models.IMSSubscriber, error) {
	return nil, nil
}
func (r *stubRepo) ListAllServingAPN(_ context.Context) ([]repository.GeoredServingAPN, error) {
	return nil, nil
}

func (r *stubRepo) UpsertSubscriber(_ context.Context, rec *models.Subscriber) error {
	r.recordUpsertSubscriber(*rec)
	return nil
}
func (r *stubRepo) DeleteSubscriberByIMSI(_ context.Context, imsi string) error {
	r.recordDeleteSubscriber(imsi)
	return nil
}
func (r *stubRepo) UpsertAUC(_ context.Context, rec *models.AUC) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.upsertAUCCalls = append(r.upsertAUCCalls, *rec)
	return nil
}
func (r *stubRepo) DeleteAUCByID(_ context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteAUCIDs = append(r.deleteAUCIDs, id)
	return nil
}
func (r *stubRepo) UpsertAPN(_ context.Context, _ *models.APN) error             { return nil }
func (r *stubRepo) DeleteAPNByID(_ context.Context, _ int) error                 { return nil }
func (r *stubRepo) UpsertIMSSubscriber(_ context.Context, _ *models.IMSSubscriber) error {
	return nil
}
func (r *stubRepo) DeleteIMSSubscriberByMSISDN(_ context.Context, _ string) error { return nil }
func (r *stubRepo) UpsertEIR(_ context.Context, _ *models.EIR) error              { return nil }
func (r *stubRepo) DeleteEIRByID(_ context.Context, _ int) error                  { return nil }

// ── helpers ───────────────────────────────────────────────────────────────────

const testToken = "supersecret"
const testNodeID = "node-a"

// buildMux returns the same mux + bearerAuth wrapper that StartServer would create,
// using a stub repository and a no-op logger. No real network listener is started.
func buildMux(store repository.Repository) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/geored/v1/events", eventsHandler(testNodeID, store, noopLogger()))
	mux.Handle("/geored/v1/snapshot", snapshotHandler(store, noopLogger()))
	mux.Handle("/geored/v1/health", healthHandler())
	return bearerAuth(testToken, mux)
}

func postBatch(t *testing.T, handler http.Handler, token string, batch Batch) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/geored/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// ── middleware tests ──────────────────────────────────────────────────────────

func TestBearerAuth_ValidToken(t *testing.T) {
	handler := buildMux(&stubRepo{})
	rr := postBatch(t, handler, testToken, Batch{Source: "other-node", Events: nil})
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}
}

func TestBearerAuth_MissingToken(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodPost, "/geored/v1/events", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rr.Code)
	}
}

func TestBearerAuth_WrongToken(t *testing.T) {
	handler := buildMux(&stubRepo{})
	rr := postBatch(t, handler, "wrongtoken", Batch{Source: "peer", Events: nil})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rr.Code)
	}
}

// ── eventsHandler tests ───────────────────────────────────────────────────────

func TestEventsHandler_WrongMethod(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodGet, "/geored/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 got %d", rr.Code)
	}
}

func TestEventsHandler_MalformedJSON(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodPost, "/geored/v1/events", strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 got %d", rr.Code)
	}
}

func TestEventsHandler_LoopPrevention(t *testing.T) {
	// Batch source == our own node_id must be silently discarded (200, no store calls).
	store := &stubRepo{}
	handler := buildMux(store)
	// Include a subscriber_put; if loop prevention breaks, UpsertSubscriber would be called.
	sub := models.Subscriber{IMSI: "001011234567890"}
	raw, _ := json.Marshal(PayloadOAMPut{Record: mustMarshal(sub)})
	batch := Batch{
		Source: testNodeID, // same as handler's nodeID → discard
		Events: []Event{
			{Type: EventSubscriberPut, Timestamp: time.Now().UTC(), Payload: raw},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.upsertSubscriberCalls) != 0 {
		t.Errorf("expected 0 UpsertSubscriber calls (loop prevention), got %d", len(store.upsertSubscriberCalls))
	}
}

// ── OAM event apply tests ─────────────────────────────────────────────────────

func TestEventsHandler_SubscriberPut(t *testing.T) {
	store := &stubRepo{}
	handler := buildMux(store)

	sub := models.Subscriber{IMSI: "001011234567890"}
	raw, _ := json.Marshal(PayloadOAMPut{Record: mustMarshal(sub)})
	batch := Batch{
		Source: "peer-node",
		Events: []Event{
			{Type: EventSubscriberPut, Timestamp: time.Now().UTC(), Payload: raw},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.upsertSubscriberCalls) != 1 {
		t.Fatalf("expected 1 UpsertSubscriber call, got %d", len(store.upsertSubscriberCalls))
	}
	if got := store.upsertSubscriberCalls[0].IMSI; got != sub.IMSI {
		t.Errorf("expected IMSI %q got %q", sub.IMSI, got)
	}
}

func TestEventsHandler_SubscriberDel(t *testing.T) {
	store := &stubRepo{}
	handler := buildMux(store)

	// subscriber_del payload is a raw PayloadOAMDel (not wrapped in PayloadOAMPut).
	delPayload, _ := json.Marshal(PayloadOAMDel{ID: "001011234567890"})
	batch := Batch{
		Source: "peer-node",
		Events: []Event{
			{Type: EventSubscriberDel, Timestamp: time.Now().UTC(), Payload: delPayload},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.deleteSubscriberIMSIs) != 1 {
		t.Fatalf("expected 1 DeleteSubscriberByIMSI call, got %d", len(store.deleteSubscriberIMSIs))
	}
	if got := store.deleteSubscriberIMSIs[0]; got != "001011234567890" {
		t.Errorf("expected IMSI %q got %q", "001011234567890", got)
	}
}

func TestEventsHandler_MultipleMixedEvents(t *testing.T) {
	store := &stubRepo{}
	handler := buildMux(store)

	sub1 := models.Subscriber{IMSI: "001010000000001"}
	sub2 := models.Subscriber{IMSI: "001010000000002"}
	raw1, _ := json.Marshal(PayloadOAMPut{Record: mustMarshal(sub1)})
	raw2, _ := json.Marshal(PayloadOAMPut{Record: mustMarshal(sub2)})
	delPayload, _ := json.Marshal(PayloadOAMDel{ID: "001010000000003"})

	batch := Batch{
		Source: "peer-node",
		Events: []Event{
			{Type: EventSubscriberPut, Timestamp: time.Now().UTC(), Payload: raw1},
			{Type: EventSubscriberPut, Timestamp: time.Now().UTC(), Payload: raw2},
			{Type: EventSubscriberDel, Timestamp: time.Now().UTC(), Payload: delPayload},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.upsertSubscriberCalls) != 2 {
		t.Errorf("expected 2 UpsertSubscriber calls, got %d", len(store.upsertSubscriberCalls))
	}
	if len(store.deleteSubscriberIMSIs) != 1 {
		t.Errorf("expected 1 DeleteSubscriberByIMSI call, got %d", len(store.deleteSubscriberIMSIs))
	}
}

func TestEventsHandler_SQNUpdate(t *testing.T) {
	store := &stubRepo{}
	handler := buildMux(store)

	// SQN in event is higher than stub's current SQN (0), so ResyncSQN should be called.
	sqnPayload, _ := json.Marshal(PayloadSQNUpdate{AUCID: 42, SQN: 9999})
	batch := Batch{
		Source: "peer-node",
		Events: []Event{
			{Type: EventSQNUpdate, Timestamp: time.Now().UTC(), Payload: sqnPayload},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}
}

func TestEventsHandler_UnknownEventType(t *testing.T) {
	// Unknown event type must not crash; handler should still return 200.
	store := &stubRepo{}
	handler := buildMux(store)

	batch := Batch{
		Source: "peer-node",
		Events: []Event{
			{Type: EventType("totally_unknown"), Timestamp: time.Now().UTC(), Payload: json.RawMessage(`{}`)},
		},
	}
	rr := postBatch(t, handler, testToken, batch)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rr.Code)
	}
}

// ── snapshotHandler tests ─────────────────────────────────────────────────────

func TestSnapshotHandler_OK(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodGet, "/geored/v1/snapshot", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	var snap Snapshot
	if err := json.NewDecoder(rr.Body).Decode(&snap); err != nil {
		t.Errorf("response is not valid Snapshot JSON: %v", err)
	}
}

func TestSnapshotHandler_WrongMethod(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodPost, "/geored/v1/snapshot", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 got %d", rr.Code)
	}
}

// ── healthHandler tests ───────────────────────────────────────────────────────

func TestHealthHandler_OK(t *testing.T) {
	handler := buildMux(&stubRepo{})
	req := httptest.NewRequest(http.MethodGet, "/geored/v1/health", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ok") {
		t.Errorf("expected body to contain \"ok\", got %q", body)
	}
}

// ── round-trip: real http.Client → httptest.NewServer ────────────────────────

func TestRoundTrip_ClientPostsToServer(t *testing.T) {
	store := &stubRepo{}
	ts := httptest.NewServer(buildMux(store))
	defer ts.Close()

	sub := models.Subscriber{IMSI: "001019999999999"}
	raw, _ := json.Marshal(PayloadOAMPut{Record: mustMarshal(sub)})
	batch := Batch{
		Source: "remote-peer",
		Events: []Event{
			{Type: EventSubscriberPut, Timestamp: time.Now().UTC(), Payload: raw},
		},
	}
	body, _ := json.Marshal(batch)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/geored/v1/events", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 got %d", resp.StatusCode)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.upsertSubscriberCalls) != 1 {
		t.Errorf("expected 1 UpsertSubscriber call, got %d", len(store.upsertSubscriberCalls))
	}
}

func TestRoundTrip_UnauthorizedRejected(t *testing.T) {
	ts := httptest.NewServer(buildMux(&stubRepo{}))
	defer ts.Close()

	batch := Batch{Source: "hacker", Events: nil}
	body, _ := json.Marshal(batch)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/geored/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header.

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", resp.StatusCode)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustMarshal(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
