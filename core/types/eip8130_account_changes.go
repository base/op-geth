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

// EIP-8130 account_changes entry type bytes. On the wire each entry is a single
// flat RLP list whose first element is the type byte: rlp([type_byte, fields...]).
const (
	accountChangeTypeCreate     = 0x00
	accountChangeTypeConfig     = 0x01
	accountChangeTypeDelegation = 0x02
)

// ChangeType is the operation performed by a SignedChange. The value is the
// on-wire operation byte; in RLP it encodes as a bare uint, and in JSON as the
// Rust enum variant name.
type ChangeType uint8

const (
	ChangeTypeAuthorizeActor      ChangeType = 0x00
	ChangeTypeRevokeActor         ChangeType = 0x01
	ChangeTypeIncrementLocalEpoch ChangeType = 0x02
	ChangeTypeLock                ChangeType = 0x03
	ChangeTypeUnlock              ChangeType = 0x04
)

func (t ChangeType) valid() bool {
	return t >= ChangeTypeAuthorizeActor && t <= ChangeTypeUnlock
}

func (t ChangeType) MarshalJSON() ([]byte, error) {
	var name string
	switch t {
	case ChangeTypeAuthorizeActor:
		name = "AuthorizeActor"
	case ChangeTypeRevokeActor:
		name = "RevokeActor"
	case ChangeTypeIncrementLocalEpoch:
		name = "IncrementLocalEpoch"
	case ChangeTypeLock:
		name = "Lock"
	case ChangeTypeUnlock:
		name = "Unlock"
	default:
		return nil, fmt.Errorf("eip8130: invalid change type %d", uint8(t))
	}
	return json.Marshal(name)
}

func (t *ChangeType) UnmarshalJSON(input []byte) error {
	var name string
	if err := json.Unmarshal(input, &name); err != nil {
		return err
	}
	switch name {
	case "AuthorizeActor":
		*t = ChangeTypeAuthorizeActor
	case "RevokeActor":
		*t = ChangeTypeRevokeActor
	case "IncrementLocalEpoch":
		*t = ChangeTypeIncrementLocalEpoch
	case "Lock":
		*t = ChangeTypeLock
	case "Unlock":
		*t = ChangeTypeUnlock
	default:
		return fmt.Errorf("eip8130: invalid change type %q", name)
	}
	return nil
}

// EncodeRLP writes the operation byte as a bare RLP uint and rejects values that
// cannot be represented by the finalized Rust enum.
func (t ChangeType) EncodeRLP(w io.Writer) error {
	if !t.valid() {
		return fmt.Errorf("eip8130: invalid change type byte 0x%x", uint8(t))
	}
	return rlp.Encode(w, uint8(t))
}

// DecodeRLP reads an operation byte and rejects values outside the finalized
// ChangeType enum.
func (t *ChangeType) DecodeRLP(s *rlp.Stream) error {
	b, err := s.Uint8()
	if err != nil {
		return err
	}
	decoded := ChangeType(b)
	if !decoded.valid() {
		return fmt.Errorf("eip8130: invalid change type byte 0x%x", b)
	}
	*t = decoded
	return nil
}

// AccountChangeChannel selects the replay domain for SignedAccountChanges.
// Local binds the current chain and uses epoch/sequence semantics; Multichain
// binds chain ID zero and uses a monotonic sequence.
type AccountChangeChannel uint8

const (
	AccountChangeChannelLocal      AccountChangeChannel = 0x00
	AccountChangeChannelMultichain AccountChangeChannel = 0x01
)

func (c AccountChangeChannel) valid() bool {
	return c == AccountChangeChannelLocal || c == AccountChangeChannelMultichain
}

func (c AccountChangeChannel) MarshalJSON() ([]byte, error) {
	switch c {
	case AccountChangeChannelLocal:
		return []byte(`"Local"`), nil
	case AccountChangeChannelMultichain:
		return []byte(`"Multichain"`), nil
	default:
		return nil, fmt.Errorf("eip8130: invalid account change channel %d", uint8(c))
	}
}

func (c *AccountChangeChannel) UnmarshalJSON(input []byte) error {
	var name string
	if err := json.Unmarshal(input, &name); err != nil {
		return err
	}
	switch name {
	case "Local":
		*c = AccountChangeChannelLocal
	case "Multichain":
		*c = AccountChangeChannelMultichain
	default:
		return fmt.Errorf("eip8130: invalid account change channel %q", name)
	}
	return nil
}

// EncodeRLP writes the channel byte as a bare RLP uint.
func (c AccountChangeChannel) EncodeRLP(w io.Writer) error {
	if !c.valid() {
		return fmt.Errorf("eip8130: invalid account change channel byte 0x%x", uint8(c))
	}
	return rlp.Encode(w, uint8(c))
}

// DecodeRLP reads a channel byte and rejects values outside the finalized enum.
func (c *AccountChangeChannel) DecodeRLP(s *rlp.Stream) error {
	b, err := s.Uint8()
	if err != nil {
		return err
	}
	decoded := AccountChangeChannel(b)
	if !decoded.valid() {
		return fmt.Errorf("eip8130: invalid account change channel byte 0x%x", b)
	}
	*c = decoded
	return nil
}

// InitialActor is an actor installed on a newly-created account. Wire form is
// rlp([actorId, authenticator, scope, policyData]); scope is stored verbatim
// (0x00 = unrestricted admin) and policyData is empty unless scope sets the
// POLICY bit.
type InitialActor struct {
	ActorID       common.Hash    `json:"actorId"`
	Authenticator common.Address `json:"authenticator"`
	Scope         uint16         `json:"scope"`
	PolicyData    hexutil.Bytes  `json:"policyData"`
}

// SignedChange is one operation in a SignedAccountChanges batch. Wire form is
// rlp([changeType, payload]); payload is operation-specific ABI data and remains
// opaque at the transaction codec layer.
type SignedChange struct {
	ChangeType ChangeType    `json:"changeType"`
	Payload    hexutil.Bytes `json:"payload"`
}

// UnmarshalJSON keeps the Rust serde shape strict: both fields are required,
// including an explicitly empty payload ("0x").
func (c *SignedChange) UnmarshalJSON(input []byte) error {
	var dec struct {
		ChangeType *ChangeType    `json:"changeType"`
		Payload    *hexutil.Bytes `json:"payload"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ChangeType == nil {
		return errors.New("eip8130: missing required field 'changeType' in signed change")
	}
	if dec.Payload == nil {
		return errors.New("eip8130: missing required field 'payload' in signed change")
	}
	*c = SignedChange{ChangeType: *dec.ChangeType, Payload: *dec.Payload}
	return nil
}

// CreateEntry is the body of an AccountChange create entry. Wire form is
// rlp([userSalt, code, [InitialActor, ...]]).
type CreateEntry struct {
	UserSalt      common.Hash    `json:"userSalt"`
	Code          hexutil.Bytes  `json:"code"`
	InitialActors []InitialActor `json:"initialActors"`
}

// SignedAccountChanges is the body of an AccountChange config-change entry.
// Wire form is rlp([channel, sequence, [SignedChange, ...], signature]).
type SignedAccountChanges struct {
	Channel   AccountChangeChannel `json:"channel"`
	Sequence  uint64               `json:"sequence"`
	Changes   []SignedChange       `json:"changes"`
	Signature hexutil.Bytes        `json:"signature"`
}

// UnmarshalJSON keeps the Rust serde shape strict. Pointer fields distinguish a
// missing field from valid zero values such as Local, sequence zero, an empty
// changes list, or an empty signature.
func (c *SignedAccountChanges) UnmarshalJSON(input []byte) error {
	var dec struct {
		Channel   *AccountChangeChannel `json:"channel"`
		Sequence  *uint64               `json:"sequence"`
		Changes   *[]SignedChange       `json:"changes"`
		Signature *hexutil.Bytes        `json:"signature"`
	}
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	switch {
	case dec.Channel == nil:
		return errors.New("eip8130: missing required field 'channel' in signed account changes")
	case dec.Sequence == nil:
		return errors.New("eip8130: missing required field 'sequence' in signed account changes")
	case dec.Changes == nil:
		return errors.New("eip8130: missing required field 'changes' in signed account changes")
	case dec.Signature == nil:
		return errors.New("eip8130: missing required field 'signature' in signed account changes")
	}
	*c = SignedAccountChanges{
		Channel:   *dec.Channel,
		Sequence:  *dec.Sequence,
		Changes:   *dec.Changes,
		Signature: *dec.Signature,
	}
	return nil
}

// Delegation is the body of an AccountChange delegation entry. Wire form is
// rlp([target]); a zero target clears the existing delegation.
type Delegation struct {
	Target common.Address `json:"target"`
}

// AccountChange is a tagged-union entry inside Eip8130Tx.AccountChanges. Exactly
// one of the body pointers is set. On the wire each entry is a single flat RLP
// list whose first element is the type byte, followed by the body fields inline:
// rlp([type_byte, body fields...]). The type byte is a genuine list element (not
// an EIP-2718-style type_byte || rlp(...) prefix), so each entry is one
// self-contained RLP item. In JSON it is the body object with an added "type"
// discriminator ("create" / "configChange" / "delegation").
type AccountChange struct {
	Create       *CreateEntry
	ConfigChange *SignedAccountChanges
	Delegation   *Delegation
}

// resolveBody returns the wire type byte, the JSON discriminator and the body
// value of the single set body pointer. It enforces the tagged-union invariant
// that exactly one of Create/ConfigChange/Delegation is set, matching the Rust
// enum, which can only ever hold a single variant. The returned body has its
// nil nested slices normalized to empty slices so JSON marshalling emits [] (to
// match serde's Vec) rather than null; the original AccountChange is never
// mutated.
func (a AccountChange) resolveBody() (typeByte byte, typ string, body interface{}, err error) {
	n := 0
	if a.Create != nil {
		n++
		cpy := *a.Create
		if cpy.InitialActors == nil {
			cpy.InitialActors = []InitialActor{}
		}
		typeByte, typ, body = accountChangeTypeCreate, "create", &cpy
	}
	if a.ConfigChange != nil {
		n++
		cpy := *a.ConfigChange
		if cpy.Changes == nil {
			cpy.Changes = []SignedChange{}
		}
		typeByte, typ, body = accountChangeTypeConfig, "configChange", &cpy
	}
	if a.Delegation != nil {
		n++
		typeByte, typ, body = accountChangeTypeDelegation, "delegation", a.Delegation
	}
	if n != 1 {
		return 0, "", nil, errors.New("eip8130: account change must set exactly one body")
	}
	return typeByte, typ, body, nil
}

// EncodeRLP writes the entry as a single flat list rlp([type_byte, body
// fields...]). The type byte is an in-list element encoded as an RLP uint (e.g.
// 0x00 -> 0x80), followed by the set body's fields inline, mirroring the Rust
// encoder.
func (a AccountChange) EncodeRLP(w io.Writer) error {
	typeByte, _, body, err := a.resolveBody()
	if err != nil {
		return err
	}

	buf := rlp.NewEncoderBuffer(w)
	list := buf.List()
	buf.WriteUint64(uint64(typeByte))

	// The body's fields are written inline (no inner list header) so the whole
	// entry is one flat list.
	switch b := body.(type) {
	case *CreateEntry:
		buf.WriteBytes(b.UserSalt[:])
		buf.WriteBytes(b.Code)
		if err := rlp.Encode(buf, b.InitialActors); err != nil {
			return err
		}
	case *SignedAccountChanges:
		if !b.Channel.valid() {
			return fmt.Errorf("eip8130: invalid account change channel byte 0x%x", uint8(b.Channel))
		}
		buf.WriteUint64(uint64(b.Channel))
		buf.WriteUint64(b.Sequence)
		if err := rlp.Encode(buf, b.Changes); err != nil {
			return err
		}
		buf.WriteBytes(b.Signature)
	case *Delegation:
		buf.WriteBytes(b.Target[:])
	default:
		return fmt.Errorf("eip8130: unexpected account change body %T", body)
	}

	buf.ListEnd(list)
	return buf.Flush()
}

// DecodeRLP reads the single flat list, reads the type byte as an RLP uint,
// dispatches on it and decodes the body fields positionally, then enforces that
// the list is fully consumed. Rejects any unknown type byte. Returns rlp.EOL at
// the end of the enclosing list so it composes with slice decoding.
func (a *AccountChange) DecodeRLP(s *rlp.Stream) error {
	if _, err := s.List(); err != nil {
		return err
	}
	typeByte, err := s.Uint8()
	if err != nil {
		return err
	}
	*a = AccountChange{}

	switch typeByte {
	case accountChangeTypeCreate:
		body := new(CreateEntry)
		if err := s.Decode(&body.UserSalt); err != nil {
			return err
		}
		var code []byte
		if err := s.Decode(&code); err != nil {
			return err
		}
		body.Code = code
		if err := s.Decode(&body.InitialActors); err != nil {
			return err
		}
		a.Create = body
	case accountChangeTypeConfig:
		body := new(SignedAccountChanges)
		if err := s.Decode(&body.Channel); err != nil {
			return err
		}
		if err := s.Decode(&body.Sequence); err != nil {
			return err
		}
		if err := s.Decode(&body.Changes); err != nil {
			return err
		}
		var signature []byte
		if err := s.Decode(&signature); err != nil {
			return err
		}
		body.Signature = signature
		a.ConfigChange = body
	case accountChangeTypeDelegation:
		body := new(Delegation)
		if err := s.Decode(&body.Target); err != nil {
			return err
		}
		a.Delegation = body
	default:
		return fmt.Errorf("eip8130: invalid account change type byte 0x%x", typeByte)
	}

	// Enforce that the list is fully consumed (no trailing elements).
	return s.ListEnd()
}

// MarshalJSON encodes the entry as its body object plus a "type" discriminator.
func (a AccountChange) MarshalJSON() ([]byte, error) {
	_, typ, body, err := a.resolveBody()
	if err != nil {
		return nil, err
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
	*a = AccountChange{}
	switch tag.Type {
	case "create":
		a.Create = new(CreateEntry)
		return json.Unmarshal(input, a.Create)
	case "configChange":
		a.ConfigChange = new(SignedAccountChanges)
		return json.Unmarshal(input, a.ConfigChange)
	case "delegation":
		a.Delegation = new(Delegation)
		return json.Unmarshal(input, a.Delegation)
	default:
		return fmt.Errorf("eip8130: unknown account change type %q", tag.Type)
	}
}
