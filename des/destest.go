package des

import (
	"fmt"
	"os"
	"testing"
)

func TestDes(t *testing.T) {
	iv := []byte("12345678")
	key := []byte("ladykill")
	plainText := []byte("hellocrypto")
	cipherText, err := DesEncrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("加密后：%s\n", string(cipherText))
	decryText, _ := DesDecrypt(cipherText, iv, key)
	fmt.Printf("解密后：%s\n", string(decryText))
	// 测试iv大小错误
	iv = []byte("ladykiller9")
	cipherText, err = DesEncrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	// 测试key大小错误
	key = []byte("ladykiller9")
	plainText = []byte("helloworld")
	cipherText, err = DesEncrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}

func Test3Des(t *testing.T) {
	iv := []byte("12345678")
	key := []byte("ladykill")
	plainText := []byte("helloworld")
	cipherText, err := TripleDesEncrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("加密后：%s\n", string(cipherText))
	decryText, _ := TripleDesDecrypt(cipherText, iv, key)
	fmt.Printf("解密后：%s\n", string(decryText))
	// 测试iv大小错误
	iv = []byte("ladykiller9")
	cipherText, err = TripleDesDecrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	// 测试key大小错误
	key = []byte("ladykiller9")
	plainText = []byte("helloworld")
	cipherText, err = TripleDesDecrypt(plainText, iv, key)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
}
