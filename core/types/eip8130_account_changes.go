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
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// accountChangeTypeDelegation is the only account_changes entry type byte on the
// launch wire. On the wire each entry is a single flat RLP list whose first
// element is the type byte: rlp([type_byte, fields...]).
const accountChangeTypeDelegation = 0x01

// Delegation is the body of an AccountChange delegation entry. Wire form is
// rlp([target]); a zero target clears the existing delegation.
type Delegation struct {
	Target common.Address `json:"target"`
}

// AccountChange is an entry inside Eip8130Tx.AccountChanges. Delegation is the
// only account change on the launch wire and must be set. On the wire the entry
// is a single flat RLP list rlp([0x01, target]); the type byte is a genuine list
// element (not an EIP-2718-style type_byte || rlp(...) prefix). In JSON it is
// the body object with an added "type":"delegation" discriminator.
type AccountChange struct {
	Delegation *Delegation
}

var errAccountChangeMissingBody = errors.New("eip8130: account change must set a delegation")

// EncodeRLP writes the entry as a single flat list rlp([type_byte, target]),
// mirroring the Rust encoder.
func (a AccountChange) EncodeRLP(w io.Writer) error {
	if a.Delegation == nil {
		return errAccountChangeMissingBody
	}
	buf := rlp.NewEncoderBuffer(w)
	list := buf.List()
	buf.WriteUint64(accountChangeTypeDelegation)
	buf.WriteBytes(a.Delegation.Target[:])
	buf.ListEnd(list)
	return buf.Flush()
}

// DecodeRLP reads the single flat list, rejects any type byte other than
// delegation, and enforces that the list is fully consumed. Returns rlp.EOL at
// the end of the enclosing list so it composes with slice decoding.
func (a *AccountChange) DecodeRLP(s *rlp.Stream) error {
	if _, err := s.List(); err != nil {
		return err
	}
	typeByte, err := s.Uint8()
	if err != nil {
		return err
	}
	if typeByte != accountChangeTypeDelegation {
		return fmt.Errorf("eip8130: invalid account change type byte 0x%x", typeByte)
	}
	body := new(Delegation)
	if err := s.Decode(&body.Target); err != nil {
		return err
	}
	*a = AccountChange{Delegation: body}
	return s.ListEnd()
}

// MarshalJSON encodes the entry as its body object plus a "type" discriminator.
func (a AccountChange) MarshalJSON() ([]byte, error) {
	if a.Delegation == nil {
		return nil, errAccountChangeMissingBody
	}
	return json.Marshal(struct {
		Type   string         `json:"type"`
		Target common.Address `json:"target"`
	}{
		Type:   "delegation",
		Target: a.Delegation.Target,
	})
}

// UnmarshalJSON accepts only the "delegation" discriminator.
func (a *AccountChange) UnmarshalJSON(input []byte) error {
	var dec struct {
		Type   string          `json:"type"`
		Target *common.Address `json:"target"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Type != "delegation" {
		return fmt.Errorf("eip8130: unknown account change type %q", dec.Type)
	}
	if dec.Target == nil {
		return errors.New("eip8130: missing required field 'target' in delegation")
	}
	*a = AccountChange{Delegation: &Delegation{Target: *dec.Target}}
	return nil
}
