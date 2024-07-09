package alignedSdk_test

import (
	"crypto/ecdsa"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"

	"alignedSdk"

	"github.com/joho/godotenv"
)

var (
	proofGeneratorAddress = "0x66f9664f97F2b50F62D13eA064982f936dE76657"
	privateKeyHex         = "0x7d2647ad2e1f6c1dce5abe2b5c3b9c8ecfe959e40b989d531bbf6624ff1c62df"
)

func loadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func getPrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(privateKeyHex[2:])
}

func getRpcClient() (*rpc.Client, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	apiKey := os.Getenv("HOLESKY_INFURA")
	return rpc.Dial(apiKey)
}

func TestSubmitMultipleGroth16(t *testing.T) {
	proof, err := loadFile("test_files/groth16_bn254/plonk.proof")
	assert.NoError(t, err)

	vk, err := loadFile("test_files/groth16_bn254/plonk.vk")
	assert.NoError(t, err)

	pub, err := loadFile("test_files/groth16_bn254/plonk_pub_input.pub")
	assert.NoError(t, err)

	privateKey, err := getPrivateKey()
	assert.NoError(t, err)

	client, err := getRpcClient()
	assert.NoError(t, err)

	groth16Data := alignedSdk.VerificationData{
		ProvingSystem:         alignedSdk.Groth16Bn254,
		Proof:                 proof,
		PublicInput:           pub,
		VerificationKey:       vk,
		VMProgramCode:         nil,
		ProofGeneratorAddress: proofGeneratorAddress,
	}

	alignment := alignedSdk.NewAligned("", client)
	alignedSdkData, err := alignment.SubmitMultiple([]alignedSdk.VerificationData{groth16Data, groth16Data}, privateKey)
	assert.NoError(t, err)
	println(alignedSdkData)
}
