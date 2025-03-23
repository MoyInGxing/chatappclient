package des

import (
	"crypto/cipher"
	"crypto/des"
	"github.com/chatappclient/errors"
	"github.com/chatappclient/util"
	"runtime"
)

// des 加密
// plainText： 明文
// iv： 初始化向量
// key：密钥
// 返回 加密后的结果和错误
func DesEncrypt(plainText, iv, key []byte) ([]byte, error) {
	if len(iv) != 8 {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesIvError)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesKeyError)
	}
	// padding plainText
	newText := util.PaddingLastGroup(plainText, des.BlockSize)
	// Create a CBC interface
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// use same one to save space
	blockMode.CryptBlocks(newText, newText)
	return newText, nil
}

// des 解密
// cipherText： 密文
// iv： 初始化向量
// key：密钥
// 返回 解密后的结果和错误
func DesDecrypt(cipherText, iv, key []byte) ([]byte, error) {
	if len(iv) != 8 {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesIvError)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesKeyError)
	}
	// Create a CBC interface
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	return util.UnpaddingLastGroup(plainText), nil
}

// 3des 加密
// plainText： 明文
// iv： 初始化向量
// key：密钥
// 返回 加密后的结果和错误
func TripleDesEncrypt(plainText, iv, key []byte) ([]byte, error) {
	if len(iv) != 8 {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesIvError)
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.TripleDesKeyError)
	}
	// padding plainText
	newText := util.PaddingLastGroup(plainText, des.BlockSize)
	// Create a CBC interface
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// use same one to save space
	blockMode.CryptBlocks(newText, newText)
	return newText, nil
}

// 3des 解密
// cipherText： 密文
// iv： 初始化向量
// key：密钥
// 返回 解密后的结果和错误
func TripleDesDecrypt(cipherText, iv, key []byte) ([]byte, error) {
	if len(iv) != 8 {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.DesIvError)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		_, file, line, _ := runtime.Caller(0)
		return nil, util.Error(file, line+1, errors.TripleDesKeyError)
	}
	// Create a CBC interface
	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	return util.UnpaddingLastGroup(plainText), nil
}
