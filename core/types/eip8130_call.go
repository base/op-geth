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
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// Call is a single call dispatched by the protocol during EIP-8130 transaction
// execution. The wire form is rlp([to, value, data]). Calls are grouped into
// phases on the transaction as [][]Call, which encodes as
// rlp([rlp([Call, ...]), ...]).
type Call struct {
	To    common.Address `json:"to"`
	Value *big.Int       `json:"value"`
	Data  hexutil.Bytes  `json:"data"`
}

// MarshalJSON encodes value as an Ethereum hex quantity. A nil in-memory value
// is the canonical zero value, matching its RLP encoding.
func (c Call) MarshalJSON() ([]byte, error) {
	value := c.Value
	if value == nil {
		value = new(big.Int)
	}
	return json.Marshal(struct {
		To    common.Address `json:"to"`
		Value *hexutil.Big   `json:"value"`
		Data  hexutil.Bytes  `json:"data"`
	}{
		To:    c.To,
		Value: (*hexutil.Big)(value),
		Data:  c.Data,
	})
}

// UnmarshalJSON accepts value as an optional Ethereum hex quantity. Omitting it
// defaults to zero for compatibility with pre-value JSON clients.
func (c *Call) UnmarshalJSON(input []byte) error {
	var dec struct {
		To    common.Address `json:"to"`
		Value *hexutil.Big   `json:"value"`
		Data  hexutil.Bytes  `json:"data"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	c.To = dec.To
	c.Value = new(big.Int)
	if dec.Value != nil {
		c.Value.Set((*big.Int)(dec.Value))
	}
	c.Data = dec.Data
	return nil
}
