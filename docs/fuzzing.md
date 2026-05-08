# HSS Fuzzing Guide

Go 1.18+ built-in fuzzing (`go test -fuzz`) is used to automatically find reliability
and security bugs in the HSS stack: panics, slice-out-of-range, nil dereferences,
type-assertion panics, and runaway allocations.

## Quick start

```bash
# Run all unit tests first to confirm everything is green.
go test ./...

# Run the race detector (catches data races in handlers).
go test -race ./...

# Fuzz a single target for 60 seconds.
go test -run='^$' -fuzz=FuzzDecode -fuzztime=60s ./internal/gsup/

# Sweep all packages (one target per package at a time; adjust fuzztime as needed).
for pkg in \
  ./internal/gsup \
  ./internal/config \
  ./internal/api \
  ./internal/diameter \
  ./internal/diameter/s6a \
  ./internal/diameter/s6c \
  ./internal/diameter/s13 \
  ./internal/diameter/sh \
  ./internal/diameter/gx \
  ./internal/diameter/cx \
  ./internal/ims \
  ./internal/crypto; do
  go test -run='^$' -fuzz=Fuzz -fuzztime=60s "$pkg"
done
```

> **Note:** `-fuzz=Fuzz` matches the first `FuzzXxx` target in the package.  
> To fuzz a specific target: `-fuzz=FuzzReadMessage`.  
> Go only runs one fuzz target per invocation.

## Reproducing a failure

When the fuzzer finds a failing input it writes it to:

```
<pkg>/testdata/fuzz/<FuzzTargetName>/<hex-hash>
```

To reproduce:

```bash
go test -run='FuzzDecode/6154f2ee633ab6dc' ./internal/gsup/
```

These files are committed as regression seeds and will be run automatically by
`go test ./...` on every future test run (no `-fuzz` flag needed).

## Corpus storage

| Location | Purpose |
|---|---|
| `<pkg>/testdata/fuzz/<Target>/` | Committed regression seeds; run on every `go test` |
| `$GOCACHE/fuzz/<module>/<pkg>/<Target>/` | Live fuzzer-generated corpus (not committed) |

## Fuzz target index

### `internal/gsup`

| Target | Covers |
|---|---|
| `FuzzDecode` | `gsup.Decode` — raw GSUP TLV message parsing |
| `FuzzParseIDResp` | `parseIDResp` — IPA ID_RESP frame parsing (regression: tagLen=0 panic) |
| `FuzzEncodeDecodeIMSIRoundTrip` | `encodeIMSI`/`decodeIMSI` round-trip |
| `FuzzGSUPHandleMessage` | GSUP handler dispatch (AIR/ULR/PUR) via `handleMessage` |

### `internal/diameter`

| Target | Covers |
|---|---|
| `FuzzReadMessage` | `diam.ReadMessage` wire-format parsing; caps declared message length at 8 KiB to prevent OOM |

### `internal/diameter/s6a`

| Target | Covers |
|---|---|
| `FuzzParseULI` | ULI byte-slice parser |
| `FuzzDecodePLMN` | 3-byte PLMN decoder (regression: no length guard) |
| `FuzzDecodeTBCDString` | TBCD digit decoder |
| `FuzzEncodeMSISDN` | MSISDN encoder + round-trip |
| `FuzzAIR`, `FuzzULR`, `FuzzPUR`, `FuzzNOR` | S6a handler level with stub Repository |

### `internal/diameter/s6c`

| Target | Covers |
|---|---|
| `FuzzEncodeMSISDNBytes` | S6c MSISDN byte encoder |
| `FuzzDecodeMSISDN` | S6c OctetString MSISDN decoder |
| `FuzzDecodeSMSMICorrelationID` | base64 SMS-MI correlation ID decoder |
| `FuzzParseDeliveryOutcome` | grouped SM-Delivery-Outcome AVP walker |
| `FuzzParseUserIdentifier` | grouped User-Identifier AVP walker |
| `FuzzExtractSMSMICorrelationID` | grouped SMS-MI-Correlation-ID AVP walker |
| `FuzzSRISR`, `FuzzRDSMR` | S6c handler level with stub Repository |

### `internal/diameter/s13`

| Target | Covers |
|---|---|
| `FuzzECR` | S13 ECR handler with minimal stub Repository |

### `internal/diameter/sh`

| Target | Covers |
|---|---|
| `FuzzDecodeTBCD` | Sh TBCD decoder |
| `FuzzShDecodeMSISDN` | Sh MSISDN byte decoder |
| `FuzzNormalizePublicIdentity` | SIP/TEL URI normalizer |
| `FuzzExtractIdentity` | grouped UDR identity AVP walker |

### `internal/diameter/gx`

| Target | Covers |
|---|---|
| `FuzzApplyTFTHandling` | TFT rewrite logic |
| `FuzzShouldRewritePermitInTFT` | TFT permit-in rewrite predicate |
| `FuzzSplitTrim` | whitespace-trimming token splitter |
| `FuzzStripAPNFQDN` | APN FQDN stripper |

### `internal/diameter/cx`

| Target | Covers |
|---|---|
| `FuzzEncodePLMN` | PLMN encoder (MCC+MNC strings to 3 bytes) |
| `FuzzNormalizeIMSI` | private identity IMSI normalizer |
| `FuzzNormalizeMSISDN` | public identity MSISDN normalizer |

### `internal/config`

| Target | Covers |
|---|---|
| `FuzzLoadFromBytes` | YAML config parse + validation (seeded with `bin/config.yaml`) |

### `internal/ims`

| Target | Covers |
|---|---|
| `FuzzEscapeXML` | `xml.EscapeText` wrapper; verifies output is valid XML |
| `FuzzNormalizeMNC` | MNC zero-padding normalizer |
| `FuzzBuildShUserData` | Sh User-Data XML renderer + re-parse assertion |
| `FuzzBuildCxUserData` | Cx IMSSubscription XML renderer |

### `internal/crypto`

| Target | Covers |
|---|---|
| `FuzzResyncCustom` | Custom Milenage resync with fuzzed Ki/OPc/resyncInfo |
| `FuzzGenerateEUTRANVectorCustom` | Custom EUTRAN vector gen; fuzz key/AMF/PLMN lengths |
| `FuzzGenerateEAPAKAVectorCustom` | Custom EAP-AKA vector gen |
| `FuzzResyncSQNFull` | Standard `emakeev/milenage` resync path; fuzz resyncInfo bytes |
| `FuzzResyncSQNFullBadKeys` | Verifies clean error on short/invalid hex Ki/OPc |

### `internal/api`

| Target | Covers |
|---|---|
| `FuzzValidateIFCProfileXMLFragment` | IFC profile XML validator |
| `FuzzCreateSubscriber` | POST /api/v1/subscriber JSON body via httptest+sqlite |
| `FuzzCreateAUC` | POST /api/v1/subscriber/auc JSON body |
| `FuzzCreateAPN` | POST /api/v1/apn JSON body |
| `FuzzCreateEIR` | POST /api/v1/eir JSON body |
| `FuzzGetSubscriberByIMSI` | GET /api/v1/subscriber/imsi/{imsi} path parameter |

## Known caveats

- **`FuzzReadMessage`**: caps `declaredLen` (Diameter header bytes 1–3) at 8 KiB.
  Inputs with a larger declared length are skipped to prevent the `fiorix/go-diameter`
  library from attempting huge allocations.
- **Handler fuzz tests** use hand-written stub `Repository` implementations (not real
  sqlite); database errors are expected and do not constitute failures.
- **API fuzz tests** use an sqlite in-memory database created once per test binary run.
- **`FuzzReadMessage`** loads only `basedict` (not per-application dicts) to keep worker
  process memory low.  Handler-level fuzz tests in sub-packages load their own dicts via
  existing `TestMain` functions.
