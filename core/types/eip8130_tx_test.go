// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func ptrAddr(b byte) *common.Address {
	a := common.Address{b}
	return &a
}

// roundTripEip8130 marshals tx, decodes it back and re-marshals it, asserting the
// canonical 2718 encoding is byte-identical across the round-trip. It returns the
// canonical encoding.
func roundTripEip8130(t *testing.T, inner *Eip8130Tx) []byte {
	t.Helper()
	enc, err := NewTx(inner).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if enc[0] != Eip8130TxType {
		t.Fatalf("type byte = %#x, want %#x", enc[0], Eip8130TxType)
	}
	var got Transaction
	if err := got.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	reEnc, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary: %v", err)
	}
	if !bytes.Equal(enc, reEnc) {
		t.Fatalf("round-trip not byte-exact:\n got %x\nwant %x", reEnc, enc)
	}
	return enc
}

// TestEip8130TxBinaryRoundTrip verifies that encoding an EIP-8130 transaction and
// decoding it back yields a byte-identical canonical encoding for the EOA,
// configured self-pay and configured-with-payer cases.
func TestEip8130TxBinaryRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name string
		tx   *Eip8130Tx
	}{
		{
			name: "eoa self-pay",
			tx: &Eip8130Tx{
				ChainID:       big.NewInt(8453),
				Sender:        nil,
				NonceKey:      big.NewInt(0),
				NonceSequence: 7,
				ValidAfter:    100,
				ValidBefore:   200,
				GasTipCap:     big.NewInt(1),
				GasFeeCap:     big.NewInt(2),
				GasLimit:      21000,
				SenderAuth:    bytes.Repeat([]byte{0xaa}, 65), // r||s||v
				PayerAuth:     nil,
			},
		},
		{
			name: "configured self-pay",
			tx: &Eip8130Tx{
				ChainID:       big.NewInt(8453),
				Sender:        ptrAddr(0x11),
				NonceKey:      big.NewInt(3),
				NonceSequence: 8,
				ValidAfter:    200,
				ValidBefore:   300,
				GasTipCap:     big.NewInt(5),
				GasFeeCap:     big.NewInt(9),
				GasLimit:      50000,
				// authenticator(20B) || data
				SenderAuth: append(bytes.Repeat([]byte{0xbb}, 20), []byte{0x01, 0x02, 0x03}...),
				PayerAuth:  nil,
			},
		},
		{
			name: "configured with payer",
			tx: &Eip8130Tx{
				ChainID:       big.NewInt(8453),
				Sender:        ptrAddr(0x22),
				NonceKey:      big.NewInt(4),
				NonceSequence: 9,
				ValidAfter:    300,
				ValidBefore:   400,
				GasTipCap:     big.NewInt(6),
				GasFeeCap:     big.NewInt(10),
				GasLimit:      60000,
				Payer:         ptrAddr(0x33),
				SenderAuth:    append(bytes.Repeat([]byte{0xcc}, 20), []byte{0x04, 0x05}...),
				PayerAuth:     append(bytes.Repeat([]byte{0xdd}, 20), []byte{0x06, 0x07}...),
			},
		},
		{
			// Non-empty account_changes/calls and a zero-but-non-nil sender, which
			// must encode distinctly from the nil EOA path (0x94 00.. vs 0x80).
			name: "non-empty changes, zero sender",
			tx: &Eip8130Tx{
				ChainID:       big.NewInt(8453),
				Sender:        ptrAddr(0x00),
				NonceKey:      big.NewInt(0),
				NonceSequence: 10,
				ValidAfter:    0,
				ValidBefore:   0,
				GasTipCap:     big.NewInt(7),
				GasFeeCap:     big.NewInt(11),
				GasLimit:      70000,
				AccountChanges: []AccountChange{
					{Delegation: &Delegation{Target: common.Address{0xdd}}},
				},
				Calls: [][]Call{
					{{To: common.Address{0xaa}, Value: big.NewInt(1), Data: []byte{0xde, 0xad, 0xbe, 0xef}}},
				},
				Payer:      nil,
				SenderAuth: append(bytes.Repeat([]byte{0xee}, 20), []byte{0x08}...),
				PayerAuth:  nil,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			roundTripEip8130(t, tt.tx)
		})
	}
}

// TestEip8130TxAccountChangesRoundTrip exercises delegation account changes and
// multi-phase calls, asserting each survives a binary round-trip byte-for-byte.
func TestEip8130TxAccountChangesRoundTrip(t *testing.T) {
	base := func() *Eip8130Tx {
		return &Eip8130Tx{
			ChainID:       big.NewInt(8453),
			Sender:        ptrAddr(0x11),
			NonceKey:      big.NewInt(0),
			NonceSequence: 7,
			GasTipCap:     big.NewInt(1),
			GasFeeCap:     big.NewInt(2),
			GasLimit:      1000000,
			SenderAuth:    bytes.Repeat([]byte{0xab}, 32),
		}
	}
	delegation := AccountChange{Delegation: &Delegation{Target: common.Address{0xdd}}}
	clearDelegation := AccountChange{Delegation: &Delegation{}}

	for _, tt := range []struct {
		name           string
		accountChanges []AccountChange
		calls          [][]Call
	}{
		{
			name:           "delegation",
			accountChanges: []AccountChange{delegation},
		},
		{
			name:           "clear delegation",
			accountChanges: []AccountChange{clearDelegation},
		},
		{
			name: "calls two phases",
			calls: [][]Call{
				{{To: common.Address{0xaa}, Data: []byte{0xde, 0xad}}},
				{
					{To: common.Address{0xbb}, Value: new(big.Int).Lsh(big.NewInt(1), 255), Data: []byte{0xbe, 0xef}},
					{To: common.Address{0xcc}, Value: big.NewInt(1_000_000_000_000_000_000), Data: []byte{0x01}},
				},
			},
		},
		{
			name:           "delegation and calls",
			accountChanges: []AccountChange{delegation},
			calls: [][]Call{
				{{To: common.Address{0xaa}, Data: []byte{0xde, 0xad, 0xbe, 0xef}}},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tx := base()
			tx.AccountChanges = tt.accountChanges
			tx.Calls = tt.calls
			roundTripEip8130(t, tx)
		})
	}
}

// TestEip8130AccountChangeWireVector locks the rlp([0x01, target]) delegation
// layout shared with base-reth and rejects the removed Keystore type bytes.
func TestEip8130AccountChangeWireVector(t *testing.T) {
	change := AccountChange{Delegation: &Delegation{Target: common.Address{0xdd}}}
	got, err := rlp.EncodeToBytes(change)
	if err != nil {
		t.Fatalf("encode delegation: %v", err)
	}
	want := common.FromHex("0xd60194dd" + strings.Repeat("00", 19))
	if !bytes.Equal(got, want) {
		t.Fatalf("delegation wire mismatch:\n got %x\nwant %x", got, want)
	}
	var decoded AccountChange
	if err := rlp.DecodeBytes(want, &decoded); err != nil {
		t.Fatalf("decode delegation vector: %v", err)
	}
	if decoded.Delegation == nil || decoded.Delegation.Target != (common.Address{0xdd}) {
		t.Fatalf("decoded delegation mismatch: %+v", decoded)
	}

	for _, typeByte := range []uint8{0x00, 0x02} {
		entry, err := rlp.EncodeToBytes([]interface{}{typeByte, common.Address{0xdd}})
		if err != nil {
			t.Fatalf("encode type byte 0x%x entry: %v", typeByte, err)
		}
		if err := rlp.DecodeBytes(entry, &decoded); err == nil ||
			!strings.Contains(err.Error(), "invalid account change type byte") {
			t.Fatalf("type byte 0x%x: want invalid-type-byte error, got %v", typeByte, err)
		}
	}
}

// TestEip8130CallWireVector locks the rlp([to, value, data]) call layout shared
// with base-reth and rejects the legacy value-less rlp([to, data]) layout.
func TestEip8130CallWireVector(t *testing.T) {
	to := common.Address{0xaa}
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	want := common.FromHex("0xdd94aa" + strings.Repeat("00", 19) + "821234" + "84deadbeef")

	got, err := rlp.EncodeToBytes(Call{To: to, Value: big.NewInt(0x1234), Data: data})
	if err != nil {
		t.Fatalf("encode call: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("call wire mismatch:\n got %x\nwant %x", got, want)
	}
	var decoded Call
	if err := rlp.DecodeBytes(want, &decoded); err != nil {
		t.Fatalf("decode call: %v", err)
	}
	if decoded.To != to || decoded.Value.Cmp(big.NewInt(0x1234)) != 0 || !bytes.Equal(decoded.Data, data) {
		t.Fatalf("decoded call mismatch: %+v", decoded)
	}

	nilValue, err := rlp.EncodeToBytes(Call{To: to, Data: data})
	if err != nil {
		t.Fatalf("encode nil-value call: %v", err)
	}
	zeroValue, err := rlp.EncodeToBytes(Call{To: to, Value: new(big.Int), Data: data})
	if err != nil {
		t.Fatalf("encode zero-value call: %v", err)
	}
	if !bytes.Equal(nilValue, zeroValue) {
		t.Fatalf("nil value must encode as zero:\n got %x\nwant %x", nilValue, zeroValue)
	}

	legacy, err := rlp.EncodeToBytes([]interface{}{to, data})
	if err != nil {
		t.Fatalf("encode legacy call: %v", err)
	}
	if err := rlp.DecodeBytes(legacy, &decoded); err == nil {
		t.Fatal("legacy [to, data] call layout decoded successfully")
	}
}

// TestEip8130CallJSONValue asserts value is a hex quantity, a nil value
// marshals as "0x0", and a missing value decodes to zero like base-reth's
// serde(default).
func TestEip8130CallJSONValue(t *testing.T) {
	out, err := json.Marshal(Call{To: common.Address{0xaa}, Data: []byte{0x01}})
	if err != nil {
		t.Fatalf("marshal nil-value call: %v", err)
	}
	want := `{"to":"0xaa00000000000000000000000000000000000000","value":"0x0","data":"0x01"}`
	if string(out) != want {
		t.Fatalf("nil-value call JSON = %s, want %s", out, want)
	}

	var decoded Call
	if err := json.Unmarshal([]byte(`{"to":"0xaa00000000000000000000000000000000000000","data":"0x01"}`), &decoded); err != nil {
		t.Fatalf("unmarshal value-less call: %v", err)
	}
	if decoded.Value == nil || decoded.Value.Sign() != 0 {
		t.Fatalf("missing value = %v, want 0", decoded.Value)
	}

	if err := json.Unmarshal([]byte(`{"to":"0xaa00000000000000000000000000000000000000","value":"0x1234","data":"0x01"}`), &decoded); err != nil {
		t.Fatalf("unmarshal call: %v", err)
	}
	if decoded.Value.Cmp(big.NewInt(0x1234)) != 0 {
		t.Fatalf("value = %v, want 0x1234", decoded.Value)
	}
}

// TestEip8130TxWireLiteralRoundTrip starts from a hand-built canonical
// 0x79||rlp(...) wire encoding with empty account_changes / calls (0xc0) and empty
// auth, decodes it, and re-encodes it. It also checks that a transaction built with
// nil account_changes / calls encodes to that same canonical wire: empty fields must
// become the RLP empty list (0xc0) so the 2718 stream keeps its full element count.
func TestEip8130TxWireLiteralRoundTrip(t *testing.T) {
	want := []byte{
		Eip8130TxType,
		0xd1,             // list, 17 payload bytes
		0x01,             // chainID = 1
		0x80,             // sender = nil
		0x80,             // nonceKey = 0
		0x07,             // nonceSequence = 7
		0x2a,             // validAfter = 42
		0x63,             // validBefore = 99
		0x01,             // gasTipCap = 1
		0x02,             // gasFeeCap = 2
		0x82, 0x52, 0x08, // gasLimit = 21000
		0xc0, // accountChanges = empty list
		0xc0, // calls = empty list
		0x80, // metadata = empty
		0x80, // payer = nil
		0x80, // senderAuth = empty
		0x80, // payerAuth = empty
	}

	var tx Transaction
	if err := tx.UnmarshalBinary(want); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	got, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire round-trip not byte-exact:\n got %x\nwant %x", got, want)
	}

	// Building with nil account_changes / calls must yield the same canonical wire.
	built := NewTx(&Eip8130Tx{
		ChainID:       big.NewInt(1),
		NonceKey:      big.NewInt(0),
		NonceSequence: 7,
		ValidAfter:    42,
		ValidBefore:   99,
		GasTipCap:     big.NewInt(1),
		GasFeeCap:     big.NewInt(2),
		GasLimit:      21000,
	})
	builtEnc, err := built.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(built): %v", err)
	}
	if !bytes.Equal(builtEnc, want) {
		t.Fatalf("nil empties not encoded as canonical 0xc0:\n got %x\nwant %x", builtEnc, want)
	}

	legacy := []byte{
		Eip8130TxType,
		0xd0,             // list, 16 payload bytes
		0x01,             // chainID = 1
		0x80,             // sender = nil
		0x80,             // nonceKey = 0
		0x07,             // nonceSequence = 7
		0x80,             // legacy expiry = 0
		0x01,             // gasTipCap = 1
		0x02,             // gasFeeCap = 2
		0x82, 0x52, 0x08, // gasLimit = 21000
		0xc0, // accountChanges = empty list
		0xc0, // calls = empty list
		0x80, // metadata = empty
		0x80, // payer = nil
		0x80, // senderAuth = empty
		0x80, // payerAuth = empty
	}
	var legacyTx Transaction
	if err := legacyTx.UnmarshalBinary(legacy); err == nil {
		t.Fatal("legacy expiry wire shape decoded successfully")
	}
}

// TestEip8130TxJSONRoundTrip verifies that the JSON representation preserves all
// EIP-8130 fields.
func TestEip8130TxJSONRoundTrip(t *testing.T) {
	tx := NewTx(&Eip8130Tx{
		ChainID:       big.NewInt(8453),
		Sender:        ptrAddr(0x22),
		NonceKey:      big.NewInt(4),
		NonceSequence: 9,
		ValidAfter:    200,
		ValidBefore:   300,
		GasTipCap:     big.NewInt(6),
		GasFeeCap:     big.NewInt(10),
		GasLimit:      60000,
		AccountChanges: []AccountChange{
			{Delegation: &Delegation{Target: common.Address{0xdd}}},
		},
		Calls: [][]Call{
			{{To: common.Address{0xaa}, Value: big.NewInt(0x1234), Data: []byte{0xde, 0xad, 0xbe, 0xef}}},
		},
		Metadata:   []byte{0xca, 0xfe},
		Payer:      ptrAddr(0x33),
		SenderAuth: append(bytes.Repeat([]byte{0xcc}, 20), []byte{0x04, 0x05}...),
		PayerAuth:  append(bytes.Repeat([]byte{0xdd}, 20), []byte{0x06, 0x07}...),
	})

	data, err := tx.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var got Transaction
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	want, _ := tx.MarshalBinary()
	have, _ := got.MarshalBinary()
	if !bytes.Equal(want, have) {
		t.Fatalf("JSON round-trip not byte-exact:\n got %x\nwant %x", have, want)
	}
}

func TestEip8130TxJSONRequiresValidityBounds(t *testing.T) {
	tx := NewTx(&Eip8130Tx{
		ChainID:       big.NewInt(8453),
		NonceKey:      big.NewInt(0),
		NonceSequence: 7,
		ValidAfter:    100,
		ValidBefore:   200,
		GasTipCap:     big.NewInt(1),
		GasFeeCap:     big.NewInt(2),
		GasLimit:      21000,
	})
	data, err := tx.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	var validBody map[string]json.RawMessage
	if err := json.Unmarshal(top["tx"], &validBody); err != nil {
		t.Fatalf("unmarshal tx body: %v", err)
	}

	tests := []struct {
		name        string
		mutate      func(map[string]json.RawMessage)
		wantMissing string
	}{
		{
			name: "validAfter",
			mutate: func(body map[string]json.RawMessage) {
				delete(body, "validAfter")
			},
			wantMissing: "validAfter",
		},
		{
			name: "validBefore",
			mutate: func(body map[string]json.RawMessage) {
				delete(body, "validBefore")
			},
			wantMissing: "validBefore",
		},
		{
			name: "legacy expiry",
			mutate: func(body map[string]json.RawMessage) {
				delete(body, "validAfter")
				delete(body, "validBefore")
				body["expiry"] = json.RawMessage(`200`)
			},
			wantMissing: "validAfter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := make(map[string]json.RawMessage, len(validBody))
			for key, value := range validBody {
				body[key] = value
			}
			tt.mutate(body)
			bodyJSON, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal tx body: %v", err)
			}
			top["tx"] = bodyJSON
			input, err := json.Marshal(top)
			if err != nil {
				t.Fatalf("marshal input: %v", err)
			}
			var got Transaction
			err = got.UnmarshalJSON(input)
			if err == nil || !strings.Contains(err.Error(), "missing required field '"+tt.wantMissing+"'") {
				t.Fatalf("want missing-%s error, got %v", tt.wantMissing, err)
			}
		})
	}
}

// TestEip8130TxCopyDeepCopy verifies that copy() produces a fully independent
// clone: mutating every inner byte slice, nested body and big.Int of the original
// after the copy must not affect the copy, and the body pointers must differ.
func TestEip8130TxCopyDeepCopy(t *testing.T) {
	orig := &Eip8130Tx{
		ChainID:       big.NewInt(8453),
		Sender:        ptrAddr(0x11),
		NonceKey:      big.NewInt(3),
		NonceSequence: 7,
		ValidAfter:    50,
		ValidBefore:   100,
		GasTipCap:     big.NewInt(1),
		GasFeeCap:     big.NewInt(2),
		GasLimit:      1000000,
		AccountChanges: []AccountChange{
			{Delegation: &Delegation{Target: common.Address{0xdd}}},
		},
		Calls:      [][]Call{{{To: common.Address{0xaa}, Value: big.NewInt(5), Data: []byte{0xde, 0xad}}}},
		Metadata:   []byte{0x01, 0x02},
		Payer:      ptrAddr(0x55),
		SenderAuth: []byte{0xee},
		PayerAuth:  []byte{0xff},
	}

	cpy := orig.copy().(*Eip8130Tx)

	// Body pointers must not alias.
	if cpy.AccountChanges[0].Delegation == orig.AccountChanges[0].Delegation {
		t.Fatal("Delegation body pointer aliases original")
	}

	// Snapshot the copy via binary encoding before mutating the original.
	before, err := NewTx(cpy).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(copy): %v", err)
	}

	// Mutate every mutable part of the original in place.
	orig.ChainID.SetInt64(9999)
	orig.NonceKey.SetInt64(8888)
	orig.GasTipCap.SetInt64(7777)
	orig.GasFeeCap.SetInt64(6666)
	orig.AccountChanges[0].Delegation.Target[0] = 0xff
	orig.Calls[0][0].Value.SetInt64(5555)
	orig.Calls[0][0].Data[0] = 0xff
	orig.Metadata[0] = 0xff
	orig.SenderAuth[0] = 0xff
	orig.PayerAuth[0] = 0xff

	after, err := NewTx(cpy).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(copy after mutation): %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("copy changed after mutating original:\n before %x\n after  %x", before, after)
	}
}

// TestEip8130AccountChangeJSON locks the delegation JSON shape and rejects the
// removed Keystore variants and a missing target.
func TestEip8130AccountChangeJSON(t *testing.T) {
	data, err := json.Marshal(AccountChange{Delegation: &Delegation{Target: common.Address{0xdd}}})
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	want := `{"type":"delegation","target":"0xdd00000000000000000000000000000000000000"}`
	if string(data) != want {
		t.Fatalf("delegation JSON = %s, want %s", data, want)
	}
	var decoded AccountChange
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if decoded.Delegation == nil || decoded.Delegation.Target != (common.Address{0xdd}) {
		t.Fatalf("decoded delegation mismatch: %+v", decoded)
	}

	for _, input := range []string{
		`{"type":"create","userSalt":"0x00","code":"0x","initialActors":[]}`,
		`{"type":"configChange","channel":"Local","sequence":0,"changes":[],"signature":"0x"}`,
	} {
		if err := json.Unmarshal([]byte(input), &decoded); err == nil ||
			!strings.Contains(err.Error(), "unknown account change type") {
			t.Fatalf("%s: want unknown-type error, got %v", input, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"type":"delegation"}`), &decoded); err == nil ||
		!strings.Contains(err.Error(), "missing required field 'target'") {
		t.Fatalf("delegation without target: want missing-target error, got %v", err)
	}
}

// TestEip8130TxJSONRethShape decodes a hand-written JSON literal in base-reth's
// exact RPC shape (mirroring rpc-types' can_serialize_eip8130) and asserts that
// op-geth accepts it, that the decoded tx re-encodes byte-stably, and that
// MarshalJSON reproduces the same nested shape (chainId as a number, nonceKey as
// "0x0", fee caps as hex quantities, nested account_changes / calls objects).
func TestEip8130TxJSONRethShape(t *testing.T) {
	senderAuth := "0x" + strings.Repeat("ab", 32)
	input := `{
		"type":"0x79",
		"tx":{
			"chainId":8453,
			"sender":"0x0000000000000000000000000000000000000011",
			"nonceKey":"0x0",
			"nonceSequence":7,
			"validAfter":0,
			"validBefore":0,
			"maxPriorityFeePerGas":"0x3b9aca00",
			"maxFeePerGas":"0x12a05f200",
			"gasLimit":1000000,
			"accountChanges":[{"type":"delegation","target":"0x00000000000000000000000000000000000000dd"}],
			"calls":[[{"to":"0x00000000000000000000000000000000000000aa","value":"0x1234","data":"0xdeadbeef"}]],
			"metadata":"0x",
			"payer":null
		},
		"senderAuth":"` + senderAuth + `",
		"payerAuth":"0x"
	}`

	var tx Transaction
	if err := tx.UnmarshalJSON([]byte(input)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if tx.Type() != Eip8130TxType {
		t.Fatalf("type = %#x, want %#x", tx.Type(), Eip8130TxType)
	}
	inner, ok := tx.inner.(*Eip8130Tx)
	if !ok {
		t.Fatalf("inner type = %T, want *Eip8130Tx", tx.inner)
	}
	if inner.ChainID.Uint64() != 8453 || inner.NonceSequence != 7 || inner.GasLimit != 1000000 {
		t.Fatalf("decoded scalars mismatch: %+v", inner)
	}
	if len(inner.AccountChanges) != 1 || inner.AccountChanges[0].Delegation == nil {
		t.Fatalf("account_changes not decoded: %+v", inner.AccountChanges)
	}
	wantTarget := common.HexToAddress("0x00000000000000000000000000000000000000dd")
	if got := inner.AccountChanges[0].Delegation.Target; got != wantTarget {
		t.Fatalf("delegation target = %x, want %x", got, wantTarget)
	}
	if len(inner.Calls) != 1 || len(inner.Calls[0]) != 1 {
		t.Fatalf("calls not decoded: %+v", inner.Calls)
	}
	wantTo := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	if got := inner.Calls[0][0]; got.To != wantTo || got.Value.Cmp(big.NewInt(0x1234)) != 0 ||
		!bytes.Equal(got.Data, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("call mismatch: %+v", got)
	}

	// Decoded tx must re-encode byte-stably through the binary codec.
	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var tx2 Transaction
	if err := tx2.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	bin2, err := tx2.MarshalBinary()
	if err != nil {
		t.Fatalf("re-MarshalBinary: %v", err)
	}
	if !bytes.Equal(bin, bin2) {
		t.Fatalf("binary not stable:\n got %x\nwant %x", bin2, bin)
	}

	// MarshalJSON must reproduce reth's nested shape and field representations.
	out, err := tx.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	for k, want := range map[string]string{
		"type":       `"0x79"`,
		"senderAuth": `"` + senderAuth + `"`,
		"payerAuth":  `"0x"`,
	} {
		if string(top[k]) != want {
			t.Fatalf("top-level %q = %s, want %s", k, top[k], want)
		}
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(top["tx"], &body); err != nil {
		t.Fatalf("unmarshal tx body: %v", err)
	}
	for k, want := range map[string]string{
		"chainId":              `8453`,    // JSON number
		"nonceKey":             `"0x0"`,   // hex quantity
		"nonceSequence":        `7`,       // JSON number
		"validAfter":           `0`,       // JSON number
		"validBefore":          `0`,       // JSON number
		"gasLimit":             `1000000`, // JSON number
		"maxPriorityFeePerGas": `"0x3b9aca00"`,
		"maxFeePerGas":         `"0x12a05f200"`,
		"metadata":             `"0x"`,
		"payer":                `null`,
		"sender":               `"0x0000000000000000000000000000000000000011"`,
	} {
		if string(body[k]) != want {
			t.Fatalf("tx body %q = %s, want %s", k, body[k], want)
		}
	}

	// Nested account_changes / calls keep reth's structured JSON shape.
	var changes []map[string]json.RawMessage
	if err := json.Unmarshal(body["accountChanges"], &changes); err != nil {
		t.Fatalf("unmarshal accountChanges: %v", err)
	}
	if len(changes) != 1 || string(changes[0]["type"]) != `"delegation"` ||
		string(changes[0]["target"]) != `"0x00000000000000000000000000000000000000dd"` {
		t.Fatalf("accountChanges shape mismatch: %s", body["accountChanges"])
	}
	var calls [][]map[string]json.RawMessage
	if err := json.Unmarshal(body["calls"], &calls); err != nil {
		t.Fatalf("unmarshal calls: %v", err)
	}
	if len(calls) != 1 || len(calls[0]) != 1 ||
		string(calls[0][0]["to"]) != `"0x00000000000000000000000000000000000000aa"` ||
		string(calls[0][0]["value"]) != `"0x1234"` ||
		string(calls[0][0]["data"]) != `"0xdeadbeef"` {
		t.Fatalf("calls shape mismatch: %s", body["calls"])
	}
}

// TestEip8130AccountChangeRejectsMalformedRLP locks the strict-decode rejection
// branches: unknown discriminants and trailing elements. Round-trip tests only
// exercise valid input, so these malformed-input paths would otherwise be
// unguarded.
func TestEip8130AccountChangeRejectsMalformedRLP(t *testing.T) {
	t.Run("unknown type byte", func(t *testing.T) {
		// [0x03]: a well-formed one-element RLP list whose type byte is not a
		// known account-change type. (0xc1 = list of 1 byte, 0x03 = type byte.)
		var ac AccountChange
		err := rlp.DecodeBytes([]byte{0xc1, 0x03}, &ac)
		if err == nil || !strings.Contains(err.Error(), "invalid account change type byte") {
			t.Fatalf("want invalid-type-byte error, got %v", err)
		}
	})

	t.Run("trailing elements", func(t *testing.T) {
		// A delegation entry [0x01, target] with an extra trailing element must be
		// rejected: the list has to be fully consumed after the body fields.
		body, err := rlp.EncodeToBytes([]interface{}{
			uint8(accountChangeTypeDelegation),
			common.Address{0xdd},
			uint8(0xff), // trailing element
		})
		if err != nil {
			t.Fatalf("encode trailing entry: %v", err)
		}

		var ac AccountChange
		if err := rlp.DecodeBytes(body, &ac); err == nil {
			t.Fatalf("want error for trailing elements, got nil")
		}
	})

}

// TestEip8130AccountChangeRequiresDelegation locks that encoding (RLP or JSON)
// an AccountChange without a delegation body errors instead of emitting an
// entry base-reth cannot decode.
func TestEip8130AccountChangeRequiresDelegation(t *testing.T) {
	var ac AccountChange
	if _, err := rlp.EncodeToBytes(ac); err == nil ||
		!strings.Contains(err.Error(), "must set a delegation") {
		t.Fatalf("EncodeRLP: want missing-delegation error, got %v", err)
	}
	if _, err := json.Marshal(ac); err == nil ||
		!strings.Contains(err.Error(), "must set a delegation") {
		t.Fatalf("MarshalJSON: want missing-delegation error, got %v", err)
	}
}

// TestEip8130TxOpenPayer locks the three payer encodings shared with base-reth:
// empty for self-pay, the single byte 0x00 for open payer mode (the zero
// address), and the 20-byte address otherwise. A 20-byte zero address and other
// lengths are rejected. It also checks Transaction.Hash, which RLP-encodes the
// inner transaction directly, agrees with the 2718 encoding.
func TestEip8130TxOpenPayer(t *testing.T) {
	for _, tt := range []struct {
		name  string
		payer *common.Address
		want  []byte
	}{
		{"self-pay", nil, []byte{0x80}},
		{"open payer", new(common.Address), []byte{0x00}},
		{"named payer", ptrAddr(0x33), append([]byte{0x94, 0x33}, make([]byte, 19)...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rlp.EncodeToBytes(eip8130Payer{addr: tt.payer})
			if err != nil {
				t.Fatalf("encode payer: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("payer wire = %x, want %x", got, tt.want)
			}

			tx := NewTx(&Eip8130Tx{
				ChainID:    big.NewInt(8453),
				NonceKey:   big.NewInt(0),
				GasTipCap:  big.NewInt(1),
				GasFeeCap:  big.NewInt(2),
				GasLimit:   21000,
				Payer:      tt.payer,
				SenderAuth: bytes.Repeat([]byte{0xab}, 65),
				PayerAuth:  bytes.Repeat([]byte{0xcd}, 65),
			})
			enc := roundTripEip8130(t, tx.inner.(*Eip8130Tx))
			if want := crypto.Keccak256Hash(enc); tx.Hash() != want {
				t.Fatalf("hash = %x, want keccak(2718 encoding) %x", tx.Hash(), want)
			}
			var decoded Transaction
			if err := decoded.UnmarshalBinary(enc); err != nil {
				t.Fatalf("UnmarshalBinary: %v", err)
			}
			switch gotPayer := decoded.Eip8130().Payer; {
			case tt.payer == nil && gotPayer != nil,
				tt.payer != nil && (gotPayer == nil || *gotPayer != *tt.payer):
				t.Fatalf("decoded payer = %v, want %v", gotPayer, tt.payer)
			}

			// The batcher reads blocks as JSON and re-encodes them, so the JSON
			// form must map back to the same wire bytes.
			data, err := tx.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			var fromJSON Transaction
			if err := fromJSON.UnmarshalJSON(data); err != nil {
				t.Fatalf("UnmarshalJSON: %v", err)
			}
			jsonEnc, err := fromJSON.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary(from JSON): %v", err)
			}
			if !bytes.Equal(jsonEnc, enc) {
				t.Fatalf("JSON round-trip not byte-exact:\n got %x\nwant %x", jsonEnc, enc)
			}
		})
	}

	for _, raw := range [][]byte{make([]byte, 20), {0x01}, make([]byte, 19)} {
		buf, err := rlp.EncodeToBytes(raw)
		if err != nil {
			t.Fatalf("encode raw payer: %v", err)
		}
		var p eip8130Payer
		if err := rlp.DecodeBytes(buf, &p); err == nil {
			t.Fatalf("payer %x decoded successfully", raw)
		}
	}
}
