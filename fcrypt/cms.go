package fcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
)

type asnContentInfo struct {
	OID           asn1.ObjectIdentifier
	EnvelopedData asnEnvelopedData `asn1:"explicit,tag:0"`
}

type asnEnvelopedData struct {
	Version              int
	OriginatorInfo       asnOriginatorInfo `asn1:"optional,implicit,tag:0"`
	RecipientInfos       []asn1.RawValue   `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     []asn1.RawValue `asn1:"optional,implicit,tag:1,set"`
}

type asnOriginatorInfo struct {
	Certs asn1.RawValue `asn1:"optional,implicit,tag:0"`
	Crls  asn1.RawValue `asn1:"optional,implicit,tag:1"`
}

// User-friendly structures
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"optional,implicit,tag:0"`
}

type IssuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

type ContentInfo struct {
	OID           asn1.ObjectIdentifier
	EnvelopedData EnvelopedData
}

type EnvelopedData struct {
	Version              int
	OriginatorInfo       OriginatorInfo
	RecipientInfos       []interface{}
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     interface{}
}

type OriginatorInfo struct {
	Certs []interface{}
	Crls  []interface{}
}

type KeyTransRecipientInfo struct {
	Version                int
	Rid                    IssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

var (
	EnvelopedDataOid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	RsaEncryptionOid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	Aes256CbcOid     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

func getRecipientInfo(raw asn1.RawValue) (interface{}, error) {
	switch raw.Tag {
	case 16:
		var ktri KeyTransRecipientInfo
		_, err := asn1.Unmarshal(raw.FullBytes, &ktri)
		if err != nil {
			return nil, err
		}
		return ktri, nil

	default:
		return nil, errors.New("getRecipientInfo: unknown tag")
	}
	return nil, nil
}

func getOriginatorInfo(oi asnOriginatorInfo) (*OriginatorInfo, error) {
	var ret OriginatorInfo

	return &ret, nil
}

func getEnvelopedData(ed asnEnvelopedData) (*EnvelopedData, error) {
	var ret EnvelopedData

	ret.Version = ed.Version
	oi, err := getOriginatorInfo(ed.OriginatorInfo)
	if err != nil {
		return nil, err
	}

	ret.OriginatorInfo = *oi
	ret.RecipientInfos = make([]interface{}, len(ed.RecipientInfos))
	for i, recipient := range ed.RecipientInfos {
		ret.RecipientInfos[i], err = getRecipientInfo(recipient)
		if err != nil {
			return nil, err
		}
	}
	ret.EncryptedContentInfo = ed.EncryptedContentInfo

	return &ret, nil
}

func getContentInfo(ci asnContentInfo) (*ContentInfo, error) {
	var ret ContentInfo

	ret.OID = ci.OID
	ed, err := getEnvelopedData(ci.EnvelopedData)
	if err != nil {
		return nil, err
	}

	ret.EnvelopedData = *ed

	return &ret, nil
}

func decryptCMSKey(ktri *KeyTransRecipientInfo,
	privKey *rsa.PrivateKey) ([]byte, error) {
	switch {
	case ktri.KeyEncryptionAlgorithm.Algorithm.Equal(RsaEncryptionOid):
		if ktri.KeyEncryptionAlgorithm.Parameters.Tag != asn1.TagNull {
			return nil, errors.New("Extra paramaters for RSA algorithm found")
		}

		key, err := privKey.Decrypt(nil, ktri.EncryptedKey, nil)
		if err != nil {
			return nil, err
		}

		log.Printf("AES KEY: %#v\n", key)
		return key, nil
	default:
		return nil, errors.New("Unknow public encryption OID")
	}
}

func decryptMessage(eci *EncryptedContentInfo, key []byte) ([]byte, error) {
	switch {
	case eci.ContentEncryptionAlgorithm.Algorithm.Equal(Aes256CbcOid):
		if eci.ContentEncryptionAlgorithm.Parameters.Tag != asn1.TagOctetString {
			return nil, errors.New("Can't find IV in extended params")
		}

		iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
		if len(iv) != 16 {
			return nil, errors.New("Invalid IV length")
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			log.Println("Can't create cipher: ", err)
			return nil, err
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		outdata := make([]byte, len(eci.EncryptedContent))
		mode.CryptBlocks(outdata, eci.EncryptedContent)

		return removePkcs7Padding(outdata, 16)

	default:
		return nil, errors.New("Unknown symmetric algorithm OID")
	}
}

func UnmarshallCMS(der []byte) (*ContentInfo, error) {
	var ci asnContentInfo

	_, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		log.Println("Error parsing CMS container:", err)
		return nil, err
	}

	if !ci.OID.Equal(EnvelopedDataOid) {
		return nil, errors.New("Unknown object identifier in ContentInfo")
	}

	return getContentInfo(ci)
}

func DecryptMessage(der []byte, key *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	ci, err := UnmarshallCMS(der)
	if err != nil {
		return nil, err
	}

	for _, recipient := range ci.EnvelopedData.RecipientInfos {
		r := recipient.(KeyTransRecipientInfo)
		if cert.SerialNumber.Cmp(r.Rid.SerialNumber) == 0 {
			dkey, err := decryptCMSKey(&r, key)
			if err != nil {
				return nil, err
			}
			return decryptMessage(&ci.EnvelopedData.EncryptedContentInfo, dkey)
		}
	}

	return nil, errors.New("Can't find suiteable recipient")
}