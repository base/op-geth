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
	"errors"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// BaseTx is a field-aware representation of a Base transaction. The nested
// account_changes and calls structures are modelled as typed Go values; the
// authorization blobs are kept as raw bytes.
type BaseTx struct {
	ChainID        *big.Int
	Sender         *common.Address `rlp:"nil"` // nil means the empty EOA path
	NonceKey       *big.Int
	NonceSequence  uint64
	ValidAfter     uint64   // inclusive lower bound in Unix seconds or milliseconds; zero disables it
	ValidBefore    uint64   // inclusive upper bound in Unix seconds or milliseconds; zero disables it
	GasTipCap      *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap      *big.Int // a.k.a. maxFeePerGas
	GasLimit       uint64
	AccountChanges []AccountChange // account-mutation entries applied before calls execute
	Calls          [][]Call        // calls grouped into phases
	Metadata       []byte          // opaque attribution bytes; not interpreted by the protocol
	Payer          *common.Address // nil means self-pay; the zero address means open payer mode
	SenderAuth     []byte
	PayerAuth      []byte
}

// baseTxRLP is the wire layout of BaseTx. It differs from BaseTx only
// in the payer encoding, which has three forms instead of rlp:"nil"'s two.
type baseTxRLP struct {
	ChainID        *big.Int
	Sender         *common.Address `rlp:"nil"`
	NonceKey       *big.Int
	NonceSequence  uint64
	ValidAfter     uint64
	ValidBefore    uint64
	GasTipCap      *big.Int
	GasFeeCap      *big.Int
	GasLimit       uint64
	AccountChanges []AccountChange
	Calls          [][]Call
	Metadata       []byte
	Payer          baseTxPayer
	SenderAuth     []byte
	PayerAuth      []byte
}

// baseTxPayer encodes the payer as an empty string for self-pay, the single
// byte 0x00 for open payer mode (the zero address), and otherwise the 20-byte
// address. A 20-byte zero address is rejected so open payer mode has a single
// encoding.
type baseTxPayer struct {
	addr *common.Address
}

func (p baseTxPayer) EncodeRLP(w io.Writer) error {
	switch {
	case p.addr == nil:
		return rlp.Encode(w, []byte{})
	case *p.addr == (common.Address{}):
		return rlp.Encode(w, []byte{0x00})
	default:
		return rlp.Encode(w, p.addr[:])
	}
}

func (p *baseTxPayer) DecodeRLP(s *rlp.Stream) error {
	raw, err := s.Bytes()
	if err != nil {
		return err
	}
	switch {
	case len(raw) == 0:
		p.addr = nil
	case len(raw) == 1 && raw[0] == 0x00:
		p.addr = new(common.Address)
	case len(raw) == common.AddressLength && common.BytesToAddress(raw) != (common.Address{}):
		addr := common.BytesToAddress(raw)
		p.addr = &addr
	default:
		return errors.New("base tx: invalid payer encoding")
	}
	return nil
}

// EncodeRLP implements rlp.Encoder. Transaction.Hash RLP-encodes the inner
// transaction directly, so the payer encoding must live here rather than only in
// encode.
func (tx *BaseTx) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &baseTxRLP{
		ChainID:        tx.ChainID,
		Sender:         tx.Sender,
		NonceKey:       tx.NonceKey,
		NonceSequence:  tx.NonceSequence,
		ValidAfter:     tx.ValidAfter,
		ValidBefore:    tx.ValidBefore,
		GasTipCap:      tx.GasTipCap,
		GasFeeCap:      tx.GasFeeCap,
		GasLimit:       tx.GasLimit,
		AccountChanges: tx.AccountChanges,
		Calls:          tx.Calls,
		Metadata:       tx.Metadata,
		Payer:          baseTxPayer{addr: tx.Payer},
		SenderAuth:     tx.SenderAuth,
		PayerAuth:      tx.PayerAuth,
	})
}

// DecodeRLP implements rlp.Decoder.
func (tx *BaseTx) DecodeRLP(s *rlp.Stream) error {
	var dec baseTxRLP
	if err := s.Decode(&dec); err != nil {
		return err
	}
	*tx = BaseTx{
		ChainID:        dec.ChainID,
		Sender:         dec.Sender,
		NonceKey:       dec.NonceKey,
		NonceSequence:  dec.NonceSequence,
		ValidAfter:     dec.ValidAfter,
		ValidBefore:    dec.ValidBefore,
		GasTipCap:      dec.GasTipCap,
		GasFeeCap:      dec.GasFeeCap,
		GasLimit:       dec.GasLimit,
		AccountChanges: dec.AccountChanges,
		Calls:          dec.Calls,
		Metadata:       dec.Metadata,
		Payer:          dec.Payer.addr,
		SenderAuth:     dec.SenderAuth,
		PayerAuth:      dec.PayerAuth,
	}
	return nil
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *BaseTx) copy() TxData {
	cpy := &BaseTx{
		Sender:         copyAddressPtr(tx.Sender),
		NonceSequence:  tx.NonceSequence,
		ValidAfter:     tx.ValidAfter,
		ValidBefore:    tx.ValidBefore,
		GasLimit:       tx.GasLimit,
		AccountChanges: copyAccountChanges(tx.AccountChanges),
		Calls:          copyCalls(tx.Calls),
		Metadata:       common.CopyBytes(tx.Metadata),
		Payer:          copyAddressPtr(tx.Payer),
		SenderAuth:     common.CopyBytes(tx.SenderAuth),
		PayerAuth:      common.CopyBytes(tx.PayerAuth),
		// These are copied below.
		ChainID:   new(big.Int),
		NonceKey:  new(big.Int),
		GasTipCap: new(big.Int),
		GasFeeCap: new(big.Int),
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.NonceKey != nil {
		cpy.NonceKey.Set(tx.NonceKey)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	return cpy
}

// accessors for innerTx.
func (tx *BaseTx) txType() byte           { return BaseTxType }
func (tx *BaseTx) chainID() *big.Int      { return tx.ChainID }
func (tx *BaseTx) accessList() AccessList { return nil }
func (tx *BaseTx) data() []byte           { return nil }
func (tx *BaseTx) gas() uint64            { return tx.GasLimit }
func (tx *BaseTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *BaseTx) gasTipCap() *big.Int    { return tx.GasTipCap }

// gasPrice returns GasFeeCap. Precondition: GasFeeCap is always non-nil; see
// effectiveGasPrice for where this is guaranteed.
func (tx *BaseTx) gasPrice() *big.Int  { return tx.GasFeeCap }
func (tx *BaseTx) value() *big.Int     { return common.Big0 }
func (tx *BaseTx) nonce() uint64       { return tx.NonceSequence }
func (tx *BaseTx) to() *common.Address { return nil }
func (tx *BaseTx) isSystemTx() bool    { return false }

// effectiveGasPrice computes the effective gas price from the fee caps and base
// fee. Precondition: GasFeeCap and GasTipCap are always non-nil. This holds
// because RLP decode always populates the *big.Int fields and JSON decode
// requires maxFeePerGas/maxPriorityFeePerGas (see UnmarshalJSON's
// missing-required-field checks); an in-memory tx is expected to set them too.
func (tx *BaseTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zeroes. A Base transaction carries its authorization in the
// sender_auth and payer_auth fields rather than in v, r, s.
func (tx *BaseTx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

// setSignatureValues only records the chain ID. A Base transaction has no canonical
// v, r, s; the authorization lives in the transaction fields.
func (tx *BaseTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = chainID
}

// copyCalls deep-copies the call phases, including each call's Value and Data, so
// the copy shares no memory with the original.
func copyCalls(calls [][]Call) [][]Call {
	if calls == nil {
		return nil
	}
	cpy := make([][]Call, len(calls))
	for i, phase := range calls {
		if phase == nil {
			continue
		}
		cpyPhase := make([]Call, len(phase))
		for j, c := range phase {
			var value *big.Int
			if c.Value != nil {
				value = new(big.Int).Set(c.Value)
			}
			cpyPhase[j] = Call{To: c.To, Value: value, Data: common.CopyBytes(c.Data)}
		}
		cpy[i] = cpyPhase
	}
	return cpy
}

// copyAccountChanges deep-copies the account-change entries, cloning the body
// pointers so the copy cannot alias the original.
func copyAccountChanges(changes []AccountChange) []AccountChange {
	if changes == nil {
		return nil
	}
	cpy := make([]AccountChange, len(changes))
	for i, ac := range changes {
		if ac.Delegation != nil {
			cpy[i] = AccountChange{Delegation: &Delegation{Target: ac.Delegation.Target}}
		}
	}
	return cpy
}

func (tx *BaseTx) encode(b *bytes.Buffer) error {
	// Empty account_changes and calls slices encode as the canonical RLP empty
	// list (0xc0), keeping the 2718 stream's element count stable.
	return rlp.Encode(b, tx)
}

func (tx *BaseTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// sigHash has no meaningful value for a Base transaction: authorization lives in the
// sender_auth and payer_auth fields, not in the canonical (v, r, s) fields, and
// any recovery uses an Base-transaction-specific payload, so the generic signing-hash
// path does not apply. It returns the zero hash as a sentinel rather than
// panicking; the signer never consumes it (modernSigner.Sender short-circuits
// 0x79 before reaching the hash path).
func (tx *BaseTx) sigHash(*big.Int) common.Hash {
	return common.Hash{}
}
