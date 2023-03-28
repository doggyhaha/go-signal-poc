package main

//X3DH from https://signal.org/docs/specifications/x3dh
//Bob and Alice are friends and want to communicate securely.
//Emulate a server that stores Bob's identity key and prekey bundle.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/agl/gcmsiv"
	"golang.org/x/crypto/hkdf"
)

type PrekeyBundle struct {
	IdentityKey PublicKey
	SignedPrekey PublicKey
	SignedPrekeySignature []byte
	OneTimePrekeys []PublicKey
}

type ReceivedPrekeyBundle struct { //this is what alice receives from server, it only has one one-time prekey or none
	IdentityKey PublicKey
	SignedPrekey PublicKey
	SignedPrekeySignature []byte
	OneTimePrekey PublicKey
	hasPrekey bool
}

func getPrekeyBundle(bundle PrekeyBundle) ReceivedPrekeyBundle {
	//alice asks server for bob's prekey bundle
	//server returns bob's prekey bundle

	if len(bundle.OneTimePrekeys) > 0 {
		return ReceivedPrekeyBundle{
			IdentityKey: bundle.IdentityKey,
			SignedPrekey: bundle.SignedPrekey,
			SignedPrekeySignature: bundle.SignedPrekeySignature,
			OneTimePrekey: bundle.OneTimePrekeys[0],
			hasPrekey: true,
		}
	} else {
		return ReceivedPrekeyBundle{
			IdentityKey: bundle.IdentityKey,
			SignedPrekey: bundle.SignedPrekey,
			SignedPrekeySignature: bundle.SignedPrekeySignature,
			hasPrekey: false,
		}
	}
}

func ECDH(priv PrivateKey, pub PublicKey) ([]byte, error) {
	return priv.SharedKey(pub)

}

func main() {
	//Alice generates a new identity key
	alicePub, alicePriv, _ := GenerateKey(rand.Reader)
	//Alice generates new ephemeral key pair.
	aliceEphemeralPub, aliceEphemeralPriv, _ := GenerateKey(rand.Reader)
	//Alice generates a new prekey pair.
	alicePrekeyPub, alicePrekeyPriv, _ := GenerateKey(rand.Reader)

	//Bob generates a new identity key pair.
	bobPub, bobPriv, _ := GenerateKey(rand.Reader)
	//Bob generates new signed prekey pair.
	bobSignedPrekeyPub, bobSignedPrekeyPriv, _ := GenerateKey(rand.Reader)
	//Bob signs his signed prekey.
	bobSignedPrekeySignature, _ := Sign(rand.Reader, bobPriv, bobSignedPrekeyPub)
	//Bob generates a new one-time prekey pair.
	bobOneTimePrekeyPub, bobOneTimePrekeyPriv, _ := GenerateKey(rand.Reader)
	//Bob stores his identity key and prekey bundle on the server.
	bobPrekeyBundle := PrekeyBundle{
		IdentityKey: bobPub,
		SignedPrekey: bobSignedPrekeyPub,
		SignedPrekeySignature: bobSignedPrekeySignature,
		OneTimePrekeys: []PublicKey{bobOneTimePrekeyPub},
	}

	//Alice asks server for Bob's prekey bundle.
	bobReceivedPrekeyBundle := getPrekeyBundle(bobPrekeyBundle)
	//Alice performs ECDHs
	IK := bobReceivedPrekeyBundle.IdentityKey
	SPK := bobReceivedPrekeyBundle.SignedPrekey
	//check SPK signature using bob identity key
	if !Verify(IK, SPK, bobReceivedPrekeyBundle.SignedPrekeySignature) {
		fmt.Println("Bob SPK signature verification failed")
		panic(1)
	}
	aliceEphemeralPrivb := aliceEphemeralPriv
	OTPK := bobReceivedPrekeyBundle.OneTimePrekey
	var sharedSecret []byte 
	dh1, _ := ECDH(alicePriv, SPK)
	dh2, _ := ECDH(aliceEphemeralPrivb, IK)
	dh3, _ := ECDH(aliceEphemeralPrivb, SPK)
	var dh4 []byte
	if bobReceivedPrekeyBundle.hasPrekey {
		dh4, _ = ECDH(aliceEphemeralPrivb, OTPK)
		sharedSecret = dh1
		sharedSecret = append(sharedSecret, dh2...)
		sharedSecret = append(sharedSecret, dh3...)
		sharedSecret = append(sharedSecret, dh4...)
	} else {
		sharedSecret = dh1
		sharedSecret = append(sharedSecret, dh2...)
		sharedSecret = append(sharedSecret, dh3...)
	}
	//Key derivation
	// material is 0xFF * 32 concatenated to sharedSecret 
	// salt is 0 filled byte sequence the lenght of hash output 

	material := make([]byte, 32)
	for i := 0; i < 32; i++ {
		material[i] = 0xFF
	}
	material = append(material, sharedSecret...)
	salt := make([]byte, 32)
	info := []byte("some infos")
	//Alice derives a symmetric key from the shared secret.
	exKey := hkdf.Extract(sha512.New, material, salt)
	//Alice derives a symmetric key from the shared secret.
	derivedKeyReader := hkdf.Expand(sha512.New, exKey, info)
	var derivedKey [32]byte
	derivedKeyReader.Read(derivedKey[:])

	fmt.Sprint(alicePub, aliceEphemeralPub, alicePrekeyPub, bobOneTimePrekeyPriv, bobOneTimePrekeyPub, bobSignedPrekeyPriv, alicePrekeyPriv)

	//alice deletes dh1, dh2, dh3, dh4, aliceEphemeralPriv 

	/*Alice then calculates an "associated data" byte sequence AD that contains identity information for both parties:

    AD = Encode(IKA) || Encode(IKB)

	Alice may optionally append additional information to AD, such as Alice and Bob's usernames, certificates, or other identifying information.

	Alice then sends Bob an initial message containing:

	Alice's identity key IKA
	Alice's ephemeral key EKA
	Identifiers stating which of Bob's prekeys Alice used
	An initial ciphertext encrypted with some AEAD encryption scheme [4] using AD as associated data and using an encryption key which is either SK or the output from some cryptographic PRF keyed by SK.*/

	// ad is these two keys separated by a 0 byte

	ad := append(alicePub, 0)
	ad = append(ad, bobPub...)
	
	//AD can be customized adding more info

	//firstmsg is "alicepub aliceephemeralpuub bobReceivedPrekeyBundle.OneTimePrekey ciphertext"

	alicepubb64 := base64.StdEncoding.EncodeToString(alicePub)
	aliceephemeralpubb64 := base64.StdEncoding.EncodeToString(aliceEphemeralPub)
	bobOTPKb64 := base64.StdEncoding.EncodeToString(OTPK)
	var input string
	fmt.Println("Insert message to send: ")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input = scanner.Text()
		break
	}
	msg := []byte(input)
	//fmt.Println(string(msg))

	hexkey := hex.EncodeToString(derivedKey[:])
	fmt.Printf("ALICE KEY: %s\n", hexkey)

	//Alice encrypts a message using the derived key.
	crypter, err := gcmsiv.NewGCMSIV(derivedKey[:])
	if err != nil {
		panic(err)
	}
	//Alice encrypts a message using the derived key.
	ciphertext := crypter.Seal(nil, nil, msg, ad)
	ciphertextb64 := base64.StdEncoding.EncodeToString(ciphertext)
	message := fmt.Sprint(alicepubb64, " ", aliceephemeralpubb64, " ", bobOTPKb64, " ", ciphertextb64, "\n")
	print(message)


	/*
	TODO:Before or after an X3DH key agreement, the parties may compare their identity public keys IKA and IKB through some authenticated channel. For example, they may compare public key fingerprints manually, or by scanning a QR code. Methods for doing this are outside the scope of this document.
	If authentication is not performed, the parties receive no cryptographic guarantee as to who they are communicating with.
	*/

	//Bob receives the message and extracts the ephemeral key and the ciphertext.
	splitted := strings.Split(message, " ")
	recAlicePub, _ := base64.StdEncoding.DecodeString(splitted[0])
	recAliceEphemeralPub, _ := base64.StdEncoding.DecodeString(splitted[1])
	recOTPK, _ := base64.StdEncoding.DecodeString(splitted[2])
	recCiphertext, _ := base64.StdEncoding.DecodeString(splitted[3])
	//Bob performs ECDHs

	var bobSharedSecret []byte
	//fmt.Println(bytes.Equal(recAlicePub, alicePubbytes))
	fmt.Println("Bob ECDH")
	bobdh1, _ := ECDH(bobSignedPrekeyPriv, recAlicePub)
	//check if bobdh1 is equal to dh1
	fmt.Println(bytes.Equal(bobdh1, dh1))
	bobdh2, _ := ECDH(bobPriv, recAliceEphemeralPub)
	fmt.Println(bytes.Equal(bobdh2, dh2))
	bobdh3, _ := ECDH(bobSignedPrekeyPriv, recAliceEphemeralPub)
	fmt.Println(bytes.Equal(bobdh3, dh3))
	bobdh4, _ := ECDH(bobOneTimePrekeyPriv, recAliceEphemeralPub)
	fmt.Println(bytes.Equal(bobdh4, dh4))
	bobSharedSecret = bobdh1
	bobSharedSecret = append(bobSharedSecret, bobdh2...)
	bobSharedSecret = append(bobSharedSecret, bobdh3...)
	bobSharedSecret = append(bobSharedSecret, bobdh4...)

	fmt.Println("Bob ECDH done")
	fmt.Println(bytes.Equal(bobSharedSecret, sharedSecret))

	//Key derivation
	// material is 0xFF * 32 concatenated to sharedSecret 
	// salt is 0 filled byte sequence the lenght of hash output 

	bobmaterial := make([]byte, 32)
	for i := 0; i < 32; i++ {
		bobmaterial[i] = 0xFF
	}
	bobmaterial = append(bobmaterial, bobSharedSecret...)
	fmt.Println(bytes.Equal(bobmaterial, material))
	bobsalt := make([]byte, 32)
	bobinfo := []byte("some infos")
	//Bob derives a symmetric key from the shared secret.
	bobexKey := hkdf.Extract(sha512.New, bobmaterial, bobsalt)
	fmt.Println(bytes.Equal(bobexKey, exKey))
	//Bob derives a symmetric key from the shared secret.
	bobderivedKeyReader := hkdf.Expand(sha512.New, bobexKey, bobinfo)
	var bobderivedKey [32]byte
	bobderivedKeyReader.Read(bobderivedKey[:])
	
	fmt.Sprint(recOTPK)

	// Bob decrypts the message

	fmt.Println(bobderivedKey == derivedKey)

	bobhexkey := hex.EncodeToString(bobderivedKey[:])
	fmt.Printf("BOB KEY: %s\n", bobhexkey)

	bobcrypted, err := gcmsiv.NewGCMSIV(bobderivedKey[:])
	if err != nil {
		panic(err)
	}

	bobplaintext, err := bobcrypted.Open(nil, nil, recCiphertext, ad)
	if err != nil {
		panic(err)
	}
	fmt.Println("Bob plaintext")
	fmt.Println(string(bobplaintext))

	/*missing features:
	1) adding more prekeys
	2) deleting used prekeys
	3) prekeys refill
	4) double ratchet (?)
	5) identity key check
	6) replay attack mitigation (useless if prekeys are always available)
	*/

}
