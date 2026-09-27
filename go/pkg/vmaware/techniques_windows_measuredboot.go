//go:build windows

package vmaware

// Port of measured_boot() (@implements VM::MEASURED_BOOT, vmaware.hpp
// ~15786-16080): fetches the crypto-agile TCG PCR event log via tbs.dll and
// looks for OVMF's known SEC/PEI phase memory bounds in a PCR0 EV_S_CRTM
// event, which is a firmware/emulator tell rather than anything a guest OS
// could spoof.

import "unsafe"

func init() {
	RegisterTechnique(MeasuredBoot, 150, measuredBootTechnique)
}

const tbsVersion20 = 2
const tbsVersion12 = 1

// measuredBootFetchLog mirrors measured_boot()'s own log-fetch sequence,
// which differs from hyper_x()'s fetchTCGLog (different log-type values
// for the _Ex path, and different TBS context version/flags for the
// fallback path).
func measuredBootFetchLog() (buf []byte, ok bool) {
	tbs := loadTBS()
	if tbs == nil {
		return nil, false
	}

	if tbs.getTCGLogEx != nil {
		for _, logType := range []uint32{0, 2} {
			var logSize uint32
			r1, _, _ := tbs.getTCGLogEx.Call(uintptr(logType), 0, uintptr(unsafe.Pointer(&logSize)))
			if (r1 == 0 || r1 == tbsInsufficientBuffer) && logSize > 0 && logSize <= 16*1024*1024 {
				b := make([]byte, logSize)
				r1, _, _ = tbs.getTCGLogEx.Call(uintptr(logType), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&logSize)))
				if r1 == 0 {
					b = b[:logSize]
					if measuredBootParseLog(b) {
						return b, true
					}
				}
			}
		}
	}

	if tbs.contextCreate != nil && tbs.getTCGLog != nil && tbs.contextClose != nil {
		type params2 struct {
			Version uint32
			Flags   uint32
		}
		type params1 struct {
			Version uint32
		}

		p2 := params2{Version: tbsVersion20, Flags: 0x6}
		var context uintptr
		r1, _, _ := tbs.contextCreate.Call(uintptr(unsafe.Pointer(&p2)), uintptr(unsafe.Pointer(&context)))
		if r1 != 0 {
			p1 := params1{Version: tbsVersion12}
			r1, _, _ = tbs.contextCreate.Call(uintptr(unsafe.Pointer(&p1)), uintptr(unsafe.Pointer(&context)))
		}

		if r1 == 0 && context != 0 {
			defer tbs.contextClose.Call(context)

			var logSize uint32
			r1, _, _ = tbs.getTCGLog.Call(context, 0, uintptr(unsafe.Pointer(&logSize)))
			if (r1 == 0 || r1 == tbsInsufficientBuffer) && logSize > 0 && logSize <= 16*1024*1024 {
				b := make([]byte, logSize)
				r1, _, _ = tbs.getTCGLog.Call(context, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&logSize)))
				if r1 == 0 {
					b = b[:logSize]
					if measuredBootParseLog(b) {
						return b, true
					}
				}
			}
		}
	}

	return nil, false
}

// measuredBootParseLog mirrors measured_boot()'s parse_log lambda: parses
// the crypto-agile TCG PCR event log and reports whether a PCR0 event
// (any type) carries OVMF's documented SEC/PEI base/length pair.
func measuredBootParseLog(log []byte) bool {
	const eventHeaderSize = 32 // sizeof(TCG_PCR_EVENT_HEADER): pcrIndex(4)+eventType(4)+digest(20)+eventSize(4)
	if len(log) < eventHeaderSize {
		return false
	}

	firstPCR := le32(log[0:4])
	firstEventType := le32(log[4:8])
	firstEventSize := le32(log[28:32])
	if firstPCR != 0 || firstEventType != 0x00000003 { // EV_NO_ACTION
		return false
	}
	if uint32(len(log))-eventHeaderSize < firstEventSize {
		return false
	}

	specIDPayload := log[eventHeaderSize : eventHeaderSize+int(firstEventSize)]
	if firstEventSize < 28 || string(specIDPayload[:15]) != "Spec ID Event03" {
		return false
	}

	numAlgs := le32(specIDPayload[24:28])
	if numAlgs == 0 || numAlgs > 16 || uint32(len(specIDPayload)) < 28+numAlgs*4 {
		return false
	}

	type algSize struct{ AlgID, DigestSize uint16 }
	activeAlgs := make([]algSize, numAlgs)
	for i := uint32(0); i < numAlgs; i++ {
		off := 28 + i*4
		activeAlgs[i] = algSize{le16(specIDPayload[off : off+2]), le16(specIDPayload[off+2 : off+4])}
	}
	getDigestSize := func(algID uint16) uint16 {
		for _, a := range activeAlgs {
			if a.AlgID == algID {
				return a.DigestSize
			}
		}
		switch algID {
		case 0x0004:
			return 20
		case 0x000B:
			return 32
		case 0x000C:
			return 48
		case 0x000D:
			return 64
		}
		return 0
	}

	currentOffset := eventHeaderSize + int(firstEventSize)
	totalSize := len(log)

	for currentOffset < totalSize {
		if totalSize-currentOffset < 12 {
			break
		}
		eventPtr := log[currentOffset:]
		pcrIndex := le32(eventPtr[0:4])
		eventType := le32(eventPtr[4:8])
		digestCount := le32(eventPtr[8:12])
		if digestCount == 0 || digestCount > 16 {
			break
		}

		localOffset := 12
		parseError := false
		for i := uint32(0); i < digestCount; i++ {
			remaining := totalSize - currentOffset
			if localOffset > remaining || remaining-localOffset < 2 {
				parseError = true
				break
			}
			algID := le16(eventPtr[localOffset : localOffset+2])
			localOffset += 2
			digestSize := int(getDigestSize(algID))
			if digestSize == 0 {
				parseError = true
				break
			}
			if totalSize-currentOffset-localOffset < digestSize {
				parseError = true
				break
			}
			localOffset += digestSize
		}
		if parseError {
			break
		}

		if totalSize-currentOffset-localOffset < 4 {
			break
		}
		eventSize := int(le32(eventPtr[localOffset : localOffset+4]))
		localOffset += 4
		if totalSize-currentOffset-localOffset < eventSize {
			break
		}
		payload := eventPtr[localOffset : localOffset+eventSize]

		if pcrIndex == 0 && eventType == 0x80000008 && eventSize >= 16 {
			baseAddr := le64(payload[0:8])
			blobLen := le64(payload[8:16])
			if (baseAddr == 0x830000 && blobLen == 0xD0000) || (baseAddr == 0x900000 && blobLen == 0xE80000) {
				return true
			}
		}

		currentOffset += localOffset + eventSize
	}

	return false
}

func measuredBootTechnique() bool {
	_, found := measuredBootFetchLog()
	return found
}
