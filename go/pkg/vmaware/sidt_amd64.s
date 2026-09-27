//go:build linux

#include "textflag.h"

// func rawSIDT(buf *byte)
//
// Encodes "SIDT [DI]" directly as its opcode bytes (0F 01 /1 with ModRM
// mod=00,reg=001,rm=111 -> 0x0F), since the Go assembler has no SIDT
// mnemonic. This stores the 10-byte IDTR pseudo-descriptor (2-byte limit +
// 8-byte base) at the address in DI -- a single hardware instruction, not
// code injection.
TEXT ·rawSIDT(SB), NOSPLIT, $0-8
	MOVQ buf+0(FP), DI
	BYTE $0x0F
	BYTE $0x01
	BYTE $0x0F
	RET
