package api

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/svinson1121/vectorcore-hss/internal/config"
	"github.com/svinson1121/vectorcore-hss/internal/models"
)

var (
	fuzzServer     *Server
	fuzzTestSrv    *httptest.Server
	fuzzServerOnce sync.Once
)

func setupFuzzServer() {
	fuzzServerOnce.Do(func() {
		db, err := gorm.Open(sqlite.Open("file:fuzz_api?mode=memory&cache=shared"), &gorm.Config{})
		if err != nil {
			panic(fmt.Sprintf("fuzz: open sqlite: %v", err))
		}
		if err := db.AutoMigrate(models.AllModels()...); err != nil {
			panic(fmt.Sprintf("fuzz: migrate: %v", err))
		}
		fuzzServer = New(db, config.APIConfig{}, zap.NewNop())
		fuzzTestSrv = httptest.NewServer(fuzzServer.auth(fuzzServer.Handler()))
	})
}

func fuzzDo(method, path string, body []byte) int {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, fuzzTestSrv.URL+path, bytes.NewReader(body))
	} else {
		req, err = http.NewRequest(method, fuzzTestSrv.URL+path, nil)
	}
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func FuzzCreateSubscriber(f *testing.F) {
	setupFuzzServer()

	f.Add(`{"imsi":"001010000000001","auc_id":1,"default_apn":0,"apn_list":""}`)
	f.Add(`{"imsi":"","auc_id":0}`)
	f.Add(`{}`)
	f.Add(`not json`)
	f.Add(`{"imsi":"` + strings.Repeat("9", 20) + `","auc_id":1}`)
	f.Add(`{"imsi":null,"auc_id":-1}`)
	f.Add(string(make([]byte, 8192)))

	f.Fuzz(func(t *testing.T, body string) {
		sc := fuzzDo(http.MethodPost, "/api/v1/subscriber", []byte(body))
		if sc != 0 && (sc < 200 || sc > 599) {
			t.Errorf("unexpected status code: %d", sc)
		}
	})
}

func FuzzCreateAUC(f *testing.F) {
	setupFuzzServer()

	f.Add(`{"ki":"000102030405060708090a0b0c0d0e0f","opc":"63bfa50ee6523365ff14c1f45f88737d","amf":"8000","imsi":"001010000000002"}`)
	f.Add(`{"ki":"","opc":"","amf":""}`)
	f.Add(`{}`)
	f.Add(`not json`)
	f.Add(`{"ki":"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ","opc":"63bfa50ee6523365ff14c1f45f88737d","amf":"8000"}`)
	f.Add(`{"ki":"` + strings.Repeat("0", 64) + `"}`)

	f.Fuzz(func(t *testing.T, body string) {
		sc := fuzzDo(http.MethodPost, "/api/v1/subscriber/auc", []byte(body))
		if sc != 0 && (sc < 200 || sc > 599) {
			t.Errorf("unexpected status code: %d", sc)
		}
	})
}

func FuzzCreateAPN(f *testing.F) {
	setupFuzzServer()

	f.Add(`{"apn":"internet","apn_ambr_down":100000,"apn_ambr_up":100000}`)
	f.Add(`{"apn":""}`)
	f.Add(`{}`)
	f.Add(`not json`)
	f.Add(`{"apn":"` + strings.Repeat("a", 512) + `"}`)

	f.Fuzz(func(t *testing.T, body string) {
		sc := fuzzDo(http.MethodPost, "/api/v1/apn", []byte(body))
		if sc != 0 && (sc < 200 || sc > 599) {
			t.Errorf("unexpected status code: %d", sc)
		}
	})
}

func FuzzCreateEIR(f *testing.F) {
	setupFuzzServer()

	f.Add(`{"imei":"353490069873730","imsi":"001010000000001","match_response_code":1}`)
	f.Add(`{"imei":""}`)
	f.Add(`{}`)
	f.Add(`not json`)
	f.Add(`{"imei":"` + strings.Repeat("1", 20) + `"}`)

	f.Fuzz(func(t *testing.T, body string) {
		sc := fuzzDo(http.MethodPost, "/api/v1/eir", []byte(body))
		if sc != 0 && (sc < 200 || sc > 599) {
			t.Errorf("unexpected status code: %d", sc)
		}
	})
}

func FuzzGetSubscriberByIMSI(f *testing.F) {
	setupFuzzServer()

	f.Add("001010000000001")
	f.Add("")
	f.Add("abc")
	f.Add(strings.Repeat("9", 20))
	f.Add("../../../etc/passwd")
	f.Add(string(make([]byte, 64)))

	f.Fuzz(func(t *testing.T, imsi string) {
		sc := fuzzDo(http.MethodGet, "/api/v1/subscriber/imsi/"+imsi, nil)
		if sc != 0 && (sc < 200 || sc > 599) {
			t.Errorf("unexpected status code: %d for IMSI %q", sc, imsi)
		}
	})
}
