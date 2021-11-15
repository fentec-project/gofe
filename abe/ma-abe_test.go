package abe_test

import (
    "testing"
    "github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
)

func TestMAABE(t *testing.T) {
    // create new MAABE struct with Global Parameters
    maabe := abe.NewMAABE()

    // create three authorities, each with two attributes
    attribs1 := []string{"auth1:at1", "auth1:at2"}
    attribs2 := []string{"auth2:at1", "auth2:at2"}
    attribs3 := []string{"auth3:at1", "auth3:at2"}
    auth1, err:= maabe.NewMAABEAuth("auth1", attribs1)
    if err != nil {
        t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
    }
    auth2, err:= maabe.NewMAABEAuth("auth2", attribs2)
    if err != nil {
        t.Fatalf("Failed generation authority %s: %v\n", "auth2", err)
    }
    auth3, err:= maabe.NewMAABEAuth("auth3", attribs3)
    if err != nil {
        t.Fatalf("Failed generation authority %s: %v\n", "auth3", err)
    }

    // create a msp struct out of the boolean formula
    msp, err := abe.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
    if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
    }

    // define the set of all public keys we use
    pks := []*abe.MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk}

    // choose a message
    msg := "Attack at dawn!"

    // encrypt the message with the decryption policy in msp
    ct, err := maabe.Encrypt(msg, msp, pks)
    if err != nil {
        t.Fatalf("Failed to encrypt: %v\n", err)
    }

    // also check for empty message
    msg_empty := ""
    _, err = maabe.Encrypt(msg_empty, msp, pks)
    assert.Error(t, err)

    // use a pub keyring that is too small
    pks_small := []*abe.MAABEPubKey{auth1.Pk}
    _, err = maabe.Encrypt(msg, msp, pks_small)
    assert.Error(t, err)

    // choose a single user's Global ID
    gid := "gid1"

    // authority 1 issues keys to user
    key11, err := maabe.GenerateAttribKey(gid, "auth1:at1", auth1.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth1:at1", err)
    }
    key12, err := maabe.GenerateAttribKey(gid, "auth1:at2", auth1.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth1:at2", err)
    }
    // authority 2 issues keys to user
    key21, err := maabe.GenerateAttribKey(gid, "auth2:at1", auth2.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth2:at1", err)
    }
    key22, err := maabe.GenerateAttribKey(gid, "auth2:at2", auth2.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth2:at2", err)
    }
    // authority 3 issues keys to user
    key31, err := maabe.GenerateAttribKey(gid, "auth3:at1", auth3.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth3:at1", err)
    }
    key32, err := maabe.GenerateAttribKey(gid, "auth3:at2", auth3.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth3:at2", err)
    }

    // try and generate key for an attribute that does not belong to the
    // authority (or does not exist)
    _, err = maabe.GenerateAttribKey(gid, "auth3:at3", auth3.Sk)
    assert.Error(t, err)

    // user tries to decrypt with different key combos
    ks1 := []*abe.MAABEKey{key11, key21, key31} // ok
    ks2 := []*abe.MAABEKey{key12, key22, key32} // ok
    ks3 := []*abe.MAABEKey{key11, key22} // not ok
    ks4 := []*abe.MAABEKey{key12, key21} // not ok
    ks5 := []*abe.MAABEKey{key31, key32} // ok

    // try to decrypt all messages
    msg1, err := maabe.Decrypt(ct, ks1)
    if err != nil {
        t.Fatalf("Error decrypting with keyset 1: %v\n", err)
    }
    assert.Equal(t, msg, msg1)

    msg2, err := maabe.Decrypt(ct, ks2)
    if err != nil {
        t.Fatalf("Error decrypting with keyset 2: %v\n", err)
    }
    assert.Equal(t, msg, msg2)

    _, err = maabe.Decrypt(ct, ks3)
    assert.Error(t, err)

    _, err = maabe.Decrypt(ct, ks4)
    assert.Error(t, err)

    msg5, err := maabe.Decrypt(ct, ks5)
    if err != nil {
        t.Fatalf("Error decrypting with keyset 5: %v\n", err)
    }
    assert.Equal(t, msg, msg5)

    // generate keys with a different GID
    gid2 := "gid2"
    // authority 1 issues keys to user
    foreignKey11, err := maabe.GenerateAttribKey(gid2, "auth1:at1", auth1.Sk)
    if err != nil {
        t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth1:at1", err)
    }
    // join two users who have sufficient attributes together, but not on their
    // own
    ks6 := []*abe.MAABEKey{foreignKey11, key21}
    // try and decrypt
    _, err = maabe.Decrypt(ct, ks6)
    assert.Error(t, err)
}

