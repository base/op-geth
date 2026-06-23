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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// Eip8130Tx is a field-aware representation of an EIP-8130 transaction. The nested
// account_changes and calls structures are modelled as typed Go values; the
// authorization blobs are kept as raw bytes.
type Eip8130Tx struct {
	ChainID        *big.Int
	Sender         *common.Address `rlp:"nil"` // nil means the empty EOA path
	NonceKey       *big.Int
	NonceSequence  uint64
	Expiry         uint64
	GasTipCap      *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap      *big.Int // a.k.a. maxFeePerGas
	GasLimit       uint64
	AccountChanges []AccountChange // account-mutation entries applied before calls execute
	Calls          [][]Call        // calls grouped into phases
	Metadata       []byte          // opaque attribution bytes; not interpreted by the protocol
	Payer          *common.Address `rlp:"nil"` // nil means self-pay
	SenderAuth     []byte
	PayerAuth      []byte
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *Eip8130Tx) copy() TxData {
	cpy := &Eip8130Tx{
		Sender:         copyAddressPtr(tx.Sender),
		NonceSequence:  tx.NonceSequence,
		Expiry:         tx.Expiry,
		GasLimit:       tx.GasLimit,
		AccountChanges: append([]AccountChange(nil), tx.AccountChanges...),
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
func (tx *Eip8130Tx) txType() byte           { return Eip8130TxType }
func (tx *Eip8130Tx) chainID() *big.Int      { return tx.ChainID }
func (tx *Eip8130Tx) accessList() AccessList { return nil }
func (tx *Eip8130Tx) data() []byte           { return nil }
func (tx *Eip8130Tx) gas() uint64            { return tx.GasLimit }
func (tx *Eip8130Tx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *Eip8130Tx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *Eip8130Tx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *Eip8130Tx) value() *big.Int        { return common.Big0 }
func (tx *Eip8130Tx) nonce() uint64          { return tx.NonceSequence }
func (tx *Eip8130Tx) to() *common.Address    { return nil }
func (tx *Eip8130Tx) isSystemTx() bool       { return false }

func (tx *Eip8130Tx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zeroes. EIP-8130 carries its authorization in the
// sender_auth and payer_auth fields rather than in v, r, s.
func (tx *Eip8130Tx) rawSignatureValues() (v, r, s *big.Int) {
	return common.Big0, common.Big0, common.Big0
}

// setSignatureValues only records the chain ID. EIP-8130 has no canonical
// v, r, s; the authorization lives in the transaction fields.
func (tx *Eip8130Tx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = chainID
}

// copyCalls deep-copies the call phases.
func copyCalls(calls [][]Call) [][]Call {
	if calls == nil {
		return nil
	}
	cpy := make([][]Call, len(calls))
	for i, phase := range calls {
		cpy[i] = append([]Call(nil), phase...)
	}
	return cpy
}

func (tx *Eip8130Tx) encode(b *bytes.Buffer) error {
	// Empty account_changes and calls slices encode as the canonical RLP empty
	// list (0xc0), keeping the 2718 stream's element count stable.
	return rlp.Encode(b, tx)
}

func (tx *Eip8130Tx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// sigHash is not implemented: EIP-8130 puts its authorization in the sender_auth
// and payer_auth fields, not in the canonical (v, r, s) fields, and any recovery
// uses an EIP-8130-specific payload, so the generic signing-hash path does not apply.
func (tx *Eip8130Tx) sigHash(*big.Int) common.Hash {
	panic("eip8130 transactions are not signed")
}
