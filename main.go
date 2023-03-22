package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"go_gf256_util/gf256"
	"reflect"
)

func main() {

	gf256Cul()

}

// 1.生成助记词
// 2.通过助记词 + 密码 生成 守护码
// 3.通过守护码 + 密码 解析出 助记词
func gf256Cul() {

	//生成熵
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		fmt.Println("NewEntropy error")
		return
	}

	//真实的助记词
	mnemonic, _ := bip39.NewMnemonic(entropy)
	fmt.Println(mnemonic)

	//密码
	y_1 := Encrypt("12abcefgdfdfdfd")
	fmt.Println("密码 = ", y_1)

	//助记词
	y0 := entropy
	fmt.Println("助记词 = ", y0)

	//守护码
	y1, _ := gf256.CalculateGuardCode(y_1, y0)
	fmt.Println("密码+助记词生成 守护码 = ", y1)

	//反推的助记词
	y02, _ := gf256.CalculateEntropy(y_1, y1)
	fmt.Println("密码+守护码生成 助记词 =", y02)

	fmt.Println("是否正确的解析：", reflect.DeepEqual(y0, y02))

	//fmt.Println(hex.EncodeToString(y02))

}

func Encrypt(source string) []byte {
	byteData, _ := hex.DecodeString(source)

	result := crypto.Keccak256(byteData)
	startIdx := len(result) - 16

	return result[startIdx:]
}
