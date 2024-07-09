package aligned

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// remove comment in prod
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

type InclusionProof struct {
	MerklePath [][]byte
}

type BatchInclusionData struct {
	BatchMerkleRoot     []byte
	BatchInclusionProof []InclusionProof
	IndexInBatch        int
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
