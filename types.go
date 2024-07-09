package alignedSdk

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// type ProtocolVersion int

type Option[T any] struct {
	IsSome bool
	Data   T
}

func NewOption[T any](data T) Option[T] {
	return Option[T]{IsSome: true, Data: data}
}

var None = Option[[]byte]{IsSome: false, Data: nil}

type ProvingSystemId int

const (
	GnarkPlonkBls12381 ProvingSystemId = 0
	GnarkPlonkBn254    ProvingSystemId = 1
	Groth16Bn254       ProvingSystemId = 2
	SP1                ProvingSystemId = 3
	Halo2KZG           ProvingSystemId = 4
	Halo2IPA           ProvingSystemId = 5
	Risc0              ProvingSystemId = 6
)

func (id ProvingSystemId) String() string {
	switch id {
	case GnarkPlonkBls12381:
		return "GnarkPlonkBls12_381"
	case GnarkPlonkBn254:
		return "GnarkPlonkBn254"
	case Groth16Bn254:
		return "Groth16Bn254"
	case SP1:
		return "SP1"
	case Halo2KZG:
		return "Halo2IPA"
	case Halo2IPA:
		return "Halo2KZG"
	case Risc0:
		return "Risc0"
	default:
		panic("Unsupported proof system ID")
	}
}

type VerificationData struct {
	ProvingSystem         ProvingSystemId `json:"proving_system"`
	Proof                 []byte
	PublicInput           []byte `json:"public_input"`
	VerificationKey       []byte `json:"verification_key"`
	VMProgramCode         []byte `json:"vm_program_code"`
	ProofGeneratorAddress string `json:"proof_generator_addr"`
}

func (v VerificationData) ToJson() string {
	return fmt.Sprintf(`{"proving_system":%s}`, v.ProvingSystem.String())
}

type VerificationDataCommitment struct {
	ProofCommitment                []byte
	PublicInputCommitment          []byte
	ProvingSystemAuxDataCommitment []byte
	ProofGeneratorAddr             []byte
}

func (data *VerificationData) ToCommitment() *VerificationDataCommitment {
	hash := sha3.NewLegacyKeccak256()

	proofCommitment := hash.Sum(data.Proof)
	hash.Reset()

	publicInputCommitment := make([]byte, 32)
	if data.PublicInput != nil {
		publicInputCommitment = hash.Sum(data.PublicInput)
		hash.Reset()
	}

	provingSystemAuxDataCommitment := make([]byte, 32)
	if data.VMProgramCode != nil {
		provingSystemAuxDataCommitment = hash.Sum(data.VMProgramCode)
		hash.Reset()
	} else if data.VerificationKey != nil {
		provingSystemAuxDataCommitment = hash.Sum(data.VerificationKey)
		hash.Reset()
	}

	proofGeneratorAddr, _ := hex.DecodeString(data.ProofGeneratorAddress)

	return &VerificationDataCommitment{
		ProofCommitment:                proofCommitment,
		PublicInputCommitment:          publicInputCommitment,
		ProvingSystemAuxDataCommitment: provingSystemAuxDataCommitment,
		ProofGeneratorAddr:             proofGeneratorAddr,
	}
}

type Signature struct {
	V int
	R string
	S string
}

type ClientMessage struct {
	VerificationData VerificationData `json:"verification_data"`
	Signature        Signature
}

func NewClientMessage(verificationData VerificationData, privateKey *ecdsa.PrivateKey) (*ClientMessage, error) {
	commitment := verificationData.ToCommitment()
	commitmentBatch := hashCommitment(commitment)
	signature, err := crypto.Sign(commitmentBatch, privateKey)
	if err != nil {
		return nil, err
	}

	r, s, v, err := ConvertSignature(signature)
	if err != nil {
		return nil, err
	}

	vInt := int(v[0])

	sig := Signature{
		V: vInt,
		R: "0x" + hex.EncodeToString(r),
		S: "0x" + hex.EncodeToString(s),
	}

	obj := ClientMessage{
		VerificationData: verificationData,
		Signature:        sig,
	}

	d, _ := json.Marshal(obj)

	fmt.Println(string(d))

	return &ClientMessage{
		VerificationData: verificationData,
		Signature:        sig,
	}, nil
}

func TransformMessage(msg ClientMessage) string {
	return fmt.Sprintf(`{"verification_data":{"proving_system":"%s","proof":%x,"pub_input":%x,"verification_key":%x,"vm_program_code":null,"proof_generator_addr":"0x66f9664f97F2b50F62D13eA064982f936dE76657"},"signature":{"r":"%s","s":"%s","v":%d}}`, msg.VerificationData.ProvingSystem.String(), msg.VerificationData.Proof, msg.VerificationData.PublicInput, msg.VerificationData.VerificationKey, msg.Signature.R, msg.Signature.S, msg.Signature.V)
}

// func createSignature(r byte, s byte, v byte) Signature {
// 	return Signature{r: r, s: s, v: v}
// }

func ConvertSignature(sig []byte) (r, s, v []byte, err error) {
	if len(sig) != 65 {
		return nil, nil, nil, errors.New("wrong length")
	}

	r = sig[:32]
	// s = sig[32:64]
	// v = sig[64:]
	s = sig[32:64]
	v = sig[64:]
	return r, s, v, nil
}

func hashCommitment(data *VerificationDataCommitment) []byte {
	hash := sha3.NewLegacyKeccak256()

	hash.Write(data.ProofCommitment)
	hash.Write(data.PublicInputCommitment)
	hash.Write(data.ProvingSystemAuxDataCommitment)
	hash.Write(data.ProofGeneratorAddr)

	return hash.Sum(nil)
}

type AlignedVerificationData struct {
	VerificationDataCommitment *VerificationDataCommitment
	BatchMerkleRoot            []byte
	BatchInclusionProof        []InclusionProof
	IndexInBatch               int
}

func NewAlignedVerificationData(commitment *VerificationDataCommitment, data BatchInclusionData) *AlignedVerificationData {
	return &AlignedVerificationData{
		VerificationDataCommitment: commitment,
		BatchMerkleRoot:            data.BatchMerkleRoot,
		BatchInclusionProof:        data.BatchInclusionProof,
		IndexInBatch:               data.IndexInBatch,
	}
}

type InclusionProof struct {
	MerklePath [][]byte
}

type BatchInclusionData struct {
	BatchMerkleRoot     []byte
	BatchInclusionProof []InclusionProof
	IndexInBatch        int
}

func (data *BatchInclusionData) FromBuffer(buffer []byte) error {
	return json.Unmarshal(buffer, data)
}
