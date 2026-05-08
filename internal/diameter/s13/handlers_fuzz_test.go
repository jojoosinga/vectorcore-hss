package s13

import (
	"bytes"
	"context"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/svinson1121/vectorcore-hss/internal/config"
	"github.com/svinson1121/vectorcore-hss/internal/diameter/basedict"
	"github.com/svinson1121/vectorcore-hss/internal/models"
	"github.com/svinson1121/vectorcore-hss/internal/repository"
)

// s13Store is a minimal in-memory Repository stub for S13 fuzz tests.
type s13Store struct{}

func (s *s13Store) GetAUCByIMSI(_ context.Context, _ string) (*models.AUC, error)                     { return nil, repository.ErrNotFound }
func (s *s13Store) GetAUCByID(_ context.Context, _ int) (*models.AUC, error)                          { return nil, repository.ErrNotFound }
func (s *s13Store) AtomicGetAndIncrementSQN(_ context.Context, _ int, _ int64) (*models.AUC, error)   { return nil, repository.ErrNotFound }
func (s *s13Store) ResyncSQN(_ context.Context, _ int, _ int64) error                                 { return nil }
func (s *s13Store) GetAlgorithmProfile(_ context.Context, _ int64) (*models.AlgorithmProfile, error)  { return nil, repository.ErrNotFound }
func (s *s13Store) GetAPNByID(_ context.Context, _ int) (*models.APN, error)                          { return nil, repository.ErrNotFound }
func (s *s13Store) GetSubscriberByIMSI(_ context.Context, _ string) (*models.Subscriber, error)       { return nil, repository.ErrNotFound }
func (s *s13Store) GetSubscriberByMSISDN(_ context.Context, _ string) (*models.Subscriber, error)     { return nil, repository.ErrNotFound }
func (s *s13Store) UpdateServingMME(_ context.Context, _ string, _ *repository.ServingMMEUpdate) error { return nil }
func (s *s13Store) UpdateServingSGSN(_ context.Context, _ string, _ *repository.ServingSGSNUpdate) error { return nil }
func (s *s13Store) UpdateServingVLR(_ context.Context, _ string, _ *repository.ServingVLRUpdate) error  { return nil }
func (s *s13Store) UpdateServingMSC(_ context.Context, _ string, _ *repository.ServingMSCUpdate) error  { return nil }
func (s *s13Store) UpdateServingAMF(_ context.Context, _ string, _ *repository.ServingAMFUpdate) error  { return nil }
func (s *s13Store) UpsertServingPDUSession(_ context.Context, _ *models.ServingPDUSession) error        { return nil }
func (s *s13Store) DeleteServingPDUSession(_ context.Context, _ string, _ int) error                    { return nil }
func (s *s13Store) ListServingPDUSessions(_ context.Context, _ string) ([]models.ServingPDUSession, error) { return nil, nil }
func (s *s13Store) GetIMSSubscriberByMSISDN(_ context.Context, _ string) (*models.IMSSubscriber, error) { return nil, repository.ErrNotFound }
func (s *s13Store) GetIMSSubscriberByIMSI(_ context.Context, _ string) (*models.IMSSubscriber, error)   { return nil, repository.ErrNotFound }
func (s *s13Store) UpdateIMSSCSCF(_ context.Context, _ string, _ *repository.IMSSCSCFUpdate) error      { return nil }
func (s *s13Store) UpdateIMSPCSCF(_ context.Context, _ string, _ *repository.IMSPCSCFUpdate) error      { return nil }
func (s *s13Store) GetIFCProfileByID(_ context.Context, _ int) (*models.IFCProfile, error)              { return nil, repository.ErrNotFound }
func (s *s13Store) GetAPNByName(_ context.Context, _ string) (*models.APN, error)                       { return nil, repository.ErrNotFound }
func (s *s13Store) GetAllChargingRules(_ context.Context) ([]models.ChargingRule, error)                 { return nil, nil }
func (s *s13Store) GetChargingRulesByNames(_ context.Context, _ []string) ([]models.ChargingRule, error) { return nil, nil }
func (s *s13Store) GetChargingRulesByIDs(_ context.Context, _ []int) ([]models.ChargingRule, error)      { return nil, nil }
func (s *s13Store) GetTFTsByGroupID(_ context.Context, _ int) ([]models.TFT, error)                     { return nil, nil }
func (s *s13Store) UpsertServingAPN(_ context.Context, _ *models.ServingAPN) error                      { return nil }
func (s *s13Store) DeleteServingAPNBySession(_ context.Context, _ string) error                         { return nil }
func (s *s13Store) GetServingAPNBySession(_ context.Context, _ string) (*models.ServingAPN, error)      { return nil, repository.ErrNotFound }
func (s *s13Store) GetServingAPNByIMSI(_ context.Context, _ string) (*models.ServingAPN, error)         { return nil, repository.ErrNotFound }
func (s *s13Store) GetServingAPNByMSISDN(_ context.Context, _ string) (*models.ServingAPN, error)       { return nil, repository.ErrNotFound }
func (s *s13Store) GetServingAPNByIdentity(_ context.Context, _ string) (*models.ServingAPN, error)     { return nil, repository.ErrNotFound }
func (s *s13Store) GetServingAPNByUEIP(_ context.Context, _ string) (*models.ServingAPN, error)         { return nil, repository.ErrNotFound }
func (s *s13Store) GetSubscriberRoutingBySubscriberAndAPN(_ context.Context, _, _ int) (*models.SubscriberRouting, error) { return nil, repository.ErrNotFound }
func (s *s13Store) GetRoamingRuleByMCCMNC(_ context.Context, _, _ string) (*models.RoamingRules, error) { return nil, repository.ErrNotFound }
func (s *s13Store) UpsertEmergencySubscriber(_ context.Context, _ *models.EmergencySubscriber) error   { return nil }
func (s *s13Store) DeleteEmergencySubscriberByIMSI(_ context.Context, _ string) error                  { return nil }
func (s *s13Store) ListEIR(_ context.Context, out *[]models.EIR) error                                  { *out = nil; return nil }
func (s *s13Store) EIRNoMatchResponse() int                                                             { return 2 }
func (s *s13Store) UpsertIMSIIMEIHistory(_ context.Context, _, _, _, _ string, _ int) error            { return nil }
func (s *s13Store) StoreMWD(_ context.Context, _ *models.MessageWaitingData) error                      { return nil }
func (s *s13Store) GetMWDForIMSI(_ context.Context, _ string) ([]models.MessageWaitingData, error)      { return nil, nil }
func (s *s13Store) DeleteMWD(_ context.Context, _, _ string) error                                      { return nil }
func (s *s13Store) InvalidateCache(_ string)                                                             {}
func (s *s13Store) ListAllAUC(_ context.Context) ([]models.AUC, error)                                  { return nil, nil }
func (s *s13Store) ListAllSubscribers(_ context.Context) ([]models.Subscriber, error)                   { return nil, nil }
func (s *s13Store) ListAllIMSSubscribers(_ context.Context) ([]models.IMSSubscriber, error)             { return nil, nil }
func (s *s13Store) ListAllServingAPN(_ context.Context) ([]repository.GeoredServingAPN, error)          { return nil, nil }
func (s *s13Store) UpsertSubscriber(_ context.Context, _ *models.Subscriber) error                      { return nil }
func (s *s13Store) DeleteSubscriberByIMSI(_ context.Context, _ string) error                            { return nil }
func (s *s13Store) UpsertAUC(_ context.Context, _ *models.AUC) error                                    { return nil }
func (s *s13Store) DeleteAUCByID(_ context.Context, _ int) error                                        { return nil }
func (s *s13Store) UpsertAPN(_ context.Context, _ *models.APN) error                                    { return nil }
func (s *s13Store) DeleteAPNByID(_ context.Context, _ int) error                                        { return nil }
func (s *s13Store) UpsertIMSSubscriber(_ context.Context, _ *models.IMSSubscriber) error                { return nil }
func (s *s13Store) DeleteIMSSubscriberByMSISDN(_ context.Context, _ string) error                       { return nil }
func (s *s13Store) UpsertEIR(_ context.Context, _ *models.EIR) error                                    { return nil }
func (s *s13Store) DeleteEIRByID(_ context.Context, _ int) error                                        { return nil }

var fuzzS13Handlers *Handlers

func init() {
	_ = basedict.Load()
	_ = LoadDict()
	cfg := &config.Config{}
	cfg.HSS.OriginHost = "hss.test.net"
	cfg.HSS.OriginRealm = "test.net"
	fuzzS13Handlers = NewHandlers(cfg, &s13Store{}, zap.NewNop())
}

func FuzzECR(f *testing.F) {
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x14,
		0x80, 0x01, 0x25, // cmd=293 ECR
		0x01, 0x00, 0x00, 0x38, // app-id S13=16777252
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x02,
	})
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		const maxInput = 512
		const maxDeclared = 512
		if len(b) < 4 || len(b) > maxInput {
			return
		}
		dl := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if dl < 20 || dl > maxDeclared {
			return
		}
		func() {
			defer func() { recover() }() //nolint:errcheck
			msg, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
			if err != nil {
				return
			}
			_, _ = fuzzS13Handlers.ECR(nil, msg)
		}()
	})
}
