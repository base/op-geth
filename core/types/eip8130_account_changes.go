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
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

// EIP-8130 account_changes entry type bytes. On the wire each entry is encoded
// as type_byte || rlp([body fields...]).
const (
	accountChangeTypeCreate     = 0x00
	accountChangeTypeConfig     = 0x01
	accountChangeTypeDelegation = 0x02
)

// ActorChangeType is the operation performed by an ActorChange. The value is the
// on-wire op byte; in RLP it encodes as a bare uint, in JSON as a string.
type ActorChangeType uint8

const (
	ActorChangeAuthorize ActorChangeType = 0x01
	ActorChangeRevoke    ActorChangeType = 0x02
)

func (t ActorChangeType) MarshalJSON() ([]byte, error) {
	switch t {
	case ActorChangeAuthorize:
		return []byte(`"Authorize"`), nil
	case ActorChangeRevoke:
		return []byte(`"Revoke"`), nil
	default:
		return nil, fmt.Errorf("eip8130: invalid actor change type %d", uint8(t))
	}
}

func (t *ActorChangeType) UnmarshalJSON(input []byte) error {
	switch string(input) {
	case `"Authorize"`:
		*t = ActorChangeAuthorize
	case `"Revoke"`:
		*t = ActorChangeRevoke
	default:
		return fmt.Errorf("eip8130: invalid actor change type %s", input)
	}
	return nil
}

// InitialActor is an actor installed on a newly-created account. Wire form is
// rlp([actorId, authenticator]).
type InitialActor struct {
	ActorID       common.Hash    `json:"actorId"`
	Authenticator common.Address `json:"authenticator"`
}

// ActorChange is a single actor authorize/revoke operation inside a ConfigChange.
// Wire form is rlp([changeType, actorId, data]); data is opaque at this layer.
type ActorChange struct {
	ChangeType ActorChangeType `json:"changeType"`
	ActorID    common.Hash     `json:"actorId"`
	Data       hexutil.Bytes   `json:"data"`
}

// CreateEntry is the body of an AccountChange create entry. Wire form is
// rlp([userSalt, code, [InitialActor, ...]]).
type CreateEntry struct {
	UserSalt      common.Hash    `json:"userSalt"`
	Code          hexutil.Bytes  `json:"code"`
	InitialActors []InitialActor `json:"initialActors"`
}

// ConfigChange is the body of an AccountChange config-change entry. Wire form is
// rlp([chainId, sequence, [ActorChange, ...], auth]).
type ConfigChange struct {
	ChainID      uint64        `json:"chainId"`
	Sequence     uint64        `json:"sequence"`
	ActorChanges []ActorChange `json:"actorChanges"`
	Auth         hexutil.Bytes `json:"auth"`
}

// Delegation is the body of an AccountChange delegation entry. Wire form is
// rlp([target]); a zero target clears the existing delegation.
type Delegation struct {
	Target common.Address `json:"target"`
}

// AccountChange is a tagged-union entry inside Eip8130Tx.AccountChanges. Exactly
// one of the body pointers is set. On the wire each entry is
// type_byte || rlp([body fields...]); in JSON it is the body object with an added
// "type" discriminator ("create" / "configChange" / "delegation").
type AccountChange struct {
	Create       *CreateEntry
	ConfigChange *ConfigChange
	Delegation   *Delegation
}

// EncodeRLP writes the entry as type_byte || rlp(body).
func (a AccountChange) EncodeRLP(w io.Writer) error {
	var (
		typeByte byte
		body     interface{}
	)
	switch {
	case a.Create != nil:
		typeByte, body = accountChangeTypeCreate, a.Create
	case a.ConfigChange != nil:
		typeByte, body = accountChangeTypeConfig, a.ConfigChange
	case a.Delegation != nil:
		typeByte, body = accountChangeTypeDelegation, a.Delegation
	default:
		return errors.New("eip8130: empty account change")
	}
	if _, err := w.Write([]byte{typeByte}); err != nil {
		return err
	}
	return rlp.Encode(w, body)
}

// DecodeRLP reads the type byte and decodes the matching body. Returns rlp.EOL
// at the end of the enclosing list so it composes with slice decoding.
func (a *AccountChange) DecodeRLP(s *rlp.Stream) error {
	typeByte, err := s.Bytes()
	if err != nil {
		return err
	}
	if len(typeByte) != 1 {
		return errors.New("eip8130: invalid account change type byte")
	}
	switch typeByte[0] {
	case accountChangeTypeCreate:
		a.Create = new(CreateEntry)
		return s.Decode(a.Create)
	case accountChangeTypeConfig:
		a.ConfigChange = new(ConfigChange)
		return s.Decode(a.ConfigChange)
	case accountChangeTypeDelegation:
		a.Delegation = new(Delegation)
		return s.Decode(a.Delegation)
	default:
		return fmt.Errorf("eip8130: invalid account change type byte 0x%x", typeByte[0])
	}
}

// MarshalJSON encodes the entry as its body object plus a "type" discriminator.
func (a AccountChange) MarshalJSON() ([]byte, error) {
	var (
		typ  string
		body interface{}
	)
	switch {
	case a.Create != nil:
		typ, body = "create", a.Create
	case a.ConfigChange != nil:
		typ, body = "configChange", a.ConfigChange
	case a.Delegation != nil:
		typ, body = "delegation", a.Delegation
	default:
		return nil, errors.New("eip8130: empty account change")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["type"], _ = json.Marshal(typ)
	return json.Marshal(fields)
}

// UnmarshalJSON dispatches on the "type" discriminator.
func (a *AccountChange) UnmarshalJSON(input []byte) error {
	var tag struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(input, &tag); err != nil {
		return err
	}
	switch tag.Type {
	case "create":
		a.Create = new(CreateEntry)
		return json.Unmarshal(input, a.Create)
	case "configChange":
		a.ConfigChange = new(ConfigChange)
		return json.Unmarshal(input, a.ConfigChange)
	case "delegation":
		a.Delegation = new(Delegation)
		return json.Unmarshal(input, a.Delegation)
	default:
		return fmt.Errorf("eip8130: unknown account change type %q", tag.Type)
	}
}
