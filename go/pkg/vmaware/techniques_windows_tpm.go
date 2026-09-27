//go:build windows

package vmaware

// Port of tpm() (@implements VM::TPM, vmaware.hpp ~16081-16832): checks the
// TPM's advertised algorithm set against the profile a real TPM 2.0 chip
// exposes (flagging a pure-software libtpm), then replays the crypto-agile
// TCG PCR event log's SHA-256 digests through software SHA-256 and compares
// the reconstructed PCR[0..7] values against what the physical TPM reports
// for those same PCRs via a raw TPM2_PCR_Read command sent through
// Tbsip_Submit_Command, flagging any mismatch outside PCR 0/6 (which some
// OEM firmware legitimately recomputes across the two reads) as a
// passed-through or otherwise tampered vTPM.
//
// Deliberate deviation from upstream: upstream computes the SHA-256 hashes
// via BCryptCreateHash/BCryptHashData/BCryptFinishHash (Windows CNG).
// Go's standard library crypto/sha256 implements the exact same,
// standardized algorithm, so it's used directly here instead of adding a
// second dynamically-resolved DLL for byte-for-byte identical output.

import (
	"crypto/sha256"
	"strings"
	"unsafe"
)

func init() {
	RegisterTechnique(TPM, 45, tpmTechnique)
}

type tpmTrackedEvent struct {
	EventType uint32
	Digest    [32]byte
}

func tpmTechnique() bool {
	tbs := loadTBS()
	if tbs == nil || tbs.contextCreate == nil || tbs.getTCGLogEx == nil || tbs.submitCommand == nil || tbs.contextClose == nil {
		return false
	}

	type tbsContextParams2 struct {
		Version  uint32
		AsUint32 uint32
	}
	params := tbsContextParams2{Version: 2, AsUint32: 5}
	var context uintptr
	r1, _, _ := tbs.contextCreate.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&context)))
	if r1 != 0 {
		return false
	}
	defer tbs.contextClose.Call(context)

	if tpmAlgorithmMismatchIsLibtpm(tbs, context) {
		return true
	}

	if man, mod, ok := getManufacturerAndModel(); ok {
		manLower, modLower := strings.ToLower(man), strings.ToLower(mod)
		if strings.Contains(manLower, "lenovo") || strings.Contains(manLower, "hp") || strings.Contains(manLower, "hewlett-packard") || strings.Contains(manLower, "acer") {
			_ = modLower
			return false
		}
	}

	logSize := uint32(0)
	r1, _, _ = tbs.getTCGLogEx.Call(0, 0, uintptr(unsafe.Pointer(&logSize)))
	if r1 != 0x80284005 && r1 != 0 {
		return false
	}
	if logSize == 0 {
		return false
	}
	logBuf := make([]byte, logSize)
	r1, _, _ = tbs.getTCGLogEx.Call(0, uintptr(unsafe.Pointer(&logBuf[0])), uintptr(unsafe.Pointer(&logSize)))
	if r1 != 0 {
		return false
	}

	pcrEvents, ok := tpmParseLogIntoPCREvents(logBuf)
	if !ok {
		return false
	}

	var reconstructed [24][32]byte
	for pcrIdx := 0; pcrIdx < 8; pcrIdx++ {
		var current [32]byte
		for _, ev := range pcrEvents[pcrIdx] {
			if ev.EventType == 0x00000003 {
				continue
			}
			var concat [64]byte
			copy(concat[:32], current[:])
			copy(concat[32:], ev.Digest[:])
			current = sha256.Sum256(concat[:])
		}
		reconstructed[pcrIdx] = current
	}

	passthroughDetected := false
	for pcrIdx := 0; pcrIdx < 8; pcrIdx++ {
		actual, actualSize, ok := tpmReadPCR(tbs, context, uint32(pcrIdx), 0x000B)
		if !ok {
			continue
		}
		if actualSize != 32 || actual != reconstructed[pcrIdx] {
			if pcrIdx != 0 && pcrIdx != 6 {
				passthroughDetected = true
			}
		}
	}

	return passthroughDetected
}

// tpmDefaultAlgorithmsProfile mirrors default_algorithms_profile.
var tpmAlgMap = map[string]uint16{
	"rsa": 0x0001, "tdes": 0x0003, "sha1": 0x0004, "hmac": 0x0005,
	"aes": 0x0006, "mgf1": 0x0007, "keyedhash": 0x0008, "xor": 0x000A,
	"sha256": 0x000B, "sha384": 0x000C, "sha512": 0x000D, "null": 0x0010,
	"rsassa": 0x0014, "rsaes": 0x0015, "rsapss": 0x0016, "oaep": 0x0017,
	"ecdsa": 0x0018, "ecdh": 0x0019, "ecdaa": 0x001A, "sm2": 0x001B,
	"ecschnorr": 0x001C, "ecmqv": 0x001D, "kdf1-sp800-56a": 0x0020,
	"kdf2": 0x0021, "kdf1-sp800-108": 0x0022, "ecc": 0x0023,
	"symcipher": 0x0025, "camellia": 0x0026, "cmac": 0x003F,
	"ctr": 0x0040, "ofb": 0x0041, "cbc": 0x0042, "cfb": 0x0043, "ecb": 0x0044,
}

var tpmDefaultAlgorithmNames = []string{
	"rsa", "tdes", "sha1", "hmac",
	"aes", "mgf1", "keyedhash", "xor", "sha256", "sha384", "sha512",
	"null", "rsassa", "rsaes", "rsapss", "oaep", "ecdsa", "ecdh", "ecdaa", "sm2", "ecschnorr", "ecmqv",
	"kdf1-sp800-56a", "kdf2", "kdf1-sp800-108", "ecc",
	"symcipher", "camellia", "cmac",
}

// tpmAlgorithmMismatchIsLibtpm mirrors tpm()'s algorithm-capability query
// (TPM2_GetCapability for TPM_CAP_ALGS) and its comparison against the
// expected profile: an exact match (rather than the partial set a real TPM
// 2.0 chip reports beyond this list) indicates a minimal software libtpm.
func tpmAlgorithmMismatchIsLibtpm(tbs *tbsProcs, context uintptr) bool {
	expected := make(map[uint16]bool)
	for _, name := range tpmDefaultAlgorithmNames {
		if id, ok := tpmAlgMap[name]; ok {
			expected[id] = true
		}
	}

	cmdAlg := []byte{
		0x80, 0x01,
		0x00, 0x00, 0x00, 0x16,
		0x00, 0x00, 0x01, 0x7A,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xFF, 0xFF,
	}
	rspAlg := make([]byte, 4096)
	rspAlgSize := uint32(len(rspAlg))
	r1, _, _ := tbs.submitCommand.Call(context, 0, 200, uintptr(unsafe.Pointer(&cmdAlg[0])), uintptr(len(cmdAlg)), uintptr(unsafe.Pointer(&rspAlg[0])), uintptr(unsafe.Pointer(&rspAlgSize)))
	if r1 != 0 || rspAlgSize < 19 {
		return false
	}

	algRC := be32(rspAlg[6:10])
	algMore := rspAlg[10]
	algCap := be32(rspAlg[11:15])
	algCount := be32(rspAlg[15:19])
	if algRC != 0 || algMore != 0 || algCap != 0 {
		return false
	}

	actual := make(map[uint16]bool)
	off := uint32(19)
	for i := uint32(0); i < algCount; i++ {
		if off+6 > rspAlgSize {
			return false
		}
		algID := be16(rspAlg[off : off+2])
		actual[algID] = true
		off += 6
	}

	if len(expected) != len(actual) {
		return false
	}
	for id := range expected {
		if !actual[id] {
			return false
		}
	}
	return true
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// tpmParseLogIntoPCREvents mirrors tpm()'s log-parsing loop: walks the
// crypto-agile TCG PCR event log, keeping only each event's SHA-256 digest
// (per PCR index 0-23).
func tpmParseLogIntoPCREvents(log []byte) ([24][]tpmTrackedEvent, bool) {
	var pcrEvents [24][]tpmTrackedEvent

	if len(log) < 32 {
		return pcrEvents, false
	}
	firstEventType := le32(log[4:8])
	firstEventSize := le32(log[28:32])
	offset := uint32(32)
	if offset+firstEventSize > uint32(len(log)) {
		return pcrEvents, false
	}
	firstEventData := log[offset : offset+firstEventSize]
	offset += firstEventSize

	algToSize := map[uint16]uint16{0x0004: 20, 0x000B: 32}
	headerParsed := false
	if firstEventType == 0x03 && firstEventSize >= 28 && string(firstEventData[:15]) == "Spec ID Event03" {
		numAlgs := le32(firstEventData[24:28])
		algOffset := uint32(28)
		hasSHA256 := false
		for i := uint32(0); i < numAlgs; i++ {
			if algOffset+4 > firstEventSize {
				break
			}
			algID := le16(firstEventData[algOffset : algOffset+2])
			digestSize := le16(firstEventData[algOffset+2 : algOffset+4])
			algToSize[algID] = digestSize
			if algID == 0x000B && digestSize == 32 {
				hasSHA256 = true
			}
			algOffset += 4
		}
		if hasSHA256 {
			headerParsed = true
		}
	}
	if !headerParsed {
		return pcrEvents, false
	}

	logSize := uint32(len(log))
	for offset < logSize {
		if offset+8 > logSize {
			return pcrEvents, false
		}
		pcrIndex := le32(log[offset : offset+4])
		eventType := le32(log[offset+4 : offset+8])
		offset += 8

		if offset+4 > logSize {
			return pcrEvents, false
		}
		digestCount := le32(log[offset : offset+4])
		offset += 4

		type tempDigest struct {
			AlgID  uint16
			Digest [64]byte
			Size   uint32
		}
		var temp []tempDigest
		hasSHA256 := false
		parseOK := true

		for i := uint32(0); i < digestCount; i++ {
			if offset+2 > logSize {
				parseOK = false
				break
			}
			algID := le16(log[offset : offset+2])
			offset += 2

			size, found := algToSize[algID]
			if !found || size > 64 {
				parseOK = false
				break
			}
			if offset+uint32(size) > logSize {
				parseOK = false
				break
			}
			if algID == 0x000B {
				hasSHA256 = true
			}
			var td tempDigest
			td.AlgID = algID
			td.Size = uint32(size)
			copy(td.Digest[:], log[offset:offset+uint32(size)])
			temp = append(temp, td)
			offset += uint32(size)
		}

		if !parseOK || !hasSHA256 {
			return pcrEvents, false
		}

		if offset+4 > logSize {
			return pcrEvents, false
		}
		eventSize := le32(log[offset : offset+4])
		offset += 4
		if offset+eventSize > logSize {
			return pcrEvents, false
		}
		offset += eventSize

		if pcrIndex < 24 {
			for _, td := range temp {
				if td.AlgID == 0x000B {
					var ev tpmTrackedEvent
					ev.EventType = eventType
					copy(ev.Digest[:], td.Digest[:32])
					pcrEvents[pcrIndex] = append(pcrEvents[pcrIndex], ev)
				}
			}
		}
	}

	return pcrEvents, true
}

// tpmReadPCR mirrors tpm()'s read_tpm_pcr lambda: builds and submits a raw
// TPM2_PCR_Read command for a single PCR/algorithm pair and parses the
// response's digest out.
func tpmReadPCR(tbs *tbsProcs, context uintptr, pcrIndex uint32, algID uint16) (digest [32]byte, size uint32, ok bool) {
	if pcrIndex >= 24 {
		return digest, 0, false
	}

	cmd := make([]byte, 20)
	cmd[0], cmd[1] = 0x80, 0x01
	cmd[2], cmd[3], cmd[4], cmd[5] = 0x00, 0x00, 0x00, 0x14
	cmd[6], cmd[7], cmd[8], cmd[9] = 0x00, 0x00, 0x01, 0x7E
	cmd[10], cmd[11], cmd[12], cmd[13] = 0x00, 0x00, 0x00, 0x01
	cmd[14] = byte(algID >> 8)
	cmd[15] = byte(algID)
	cmd[16] = 0x03
	cmd[17], cmd[18], cmd[19] = 0x00, 0x00, 0x00
	cmd[17+pcrIndex/8] = 1 << (pcrIndex % 8)

	resp := make([]byte, 256)
	respSize := uint32(len(resp))
	r1, _, _ := tbs.submitCommand.Call(context, 0, 200, uintptr(unsafe.Pointer(&cmd[0])), uintptr(len(cmd)), uintptr(unsafe.Pointer(&resp[0])), uintptr(unsafe.Pointer(&respSize)))
	if r1 != 0 || respSize < 10 {
		return digest, 0, false
	}

	code := be32(resp[6:10])
	if code != 0 {
		return digest, 0, false
	}

	offset := uint32(14)
	if offset+4 > respSize {
		return digest, 0, false
	}
	selCount := be32(resp[offset : offset+4])
	offset += 4
	if selCount != 1 {
		return digest, 0, false
	}

	offset += 2
	if offset+1 > respSize {
		return digest, 0, false
	}
	retSizeofSelect := uint32(resp[offset])
	offset += 1 + retSizeofSelect

	if offset+4 > respSize {
		return digest, 0, false
	}
	digestCount := be32(resp[offset : offset+4])
	offset += 4
	if digestCount != 1 {
		return digest, 0, false
	}

	if offset+2 > respSize {
		return digest, 0, false
	}
	digestSize := be16(resp[offset : offset+2])
	offset += 2

	if offset+uint32(digestSize) > respSize {
		return digest, 0, false
	}

	copyLen := digestSize
	if copyLen > 32 {
		copyLen = 32
	}
	copy(digest[:], resp[offset:offset+uint32(copyLen)])

	return digest, uint32(digestSize), true
}
