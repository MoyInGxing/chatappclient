package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/chatappclient/des"
	"github.com/chatappclient/ecc"
	"golang.org/x/net/websocket"
	"io"
	"log"
	"os"
	"sync"
)

var Ctools CryptoTools = CryptoTools{}

type CryptoTools struct {
}

func (c *CryptoTools) AesCrypto(plaintext []byte) (ciphertext []byte, key []byte, iv []byte) {
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return
}
func (c *CryptoTools) DesCrypto(plaintext []byte) (ciphertext []byte, key []byte, iv []byte) {
	iv = []byte("12345678")
	key = []byte("ladykill")
	
	ciphertext, err := des.DesEncrypt(plaintext, iv, key)
	if err != nil {
		panic("des encrypt error")
	}
	return
}
func (c *CryptoTools) DesDecrypt(cipherText, iv, key []byte) (plaintext []byte) {
	iv = []byte("12345678")
	key = []byte("ladykill")
	plaintext, _ = des.DesDecrypt(cipherText, iv, key)
	return
}

func (c *CryptoTools) AesDecrypt(ciphertext []byte, key []byte, iv []byte) (plaintext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], ciphertext[aes.BlockSize:])
	return ciphertext[aes.BlockSize:]
}

func (c *CryptoTools) RsaCrypto(plaintext []byte) (ciphertext []byte, privateKeyBytes []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	privateKeyBytes = x509.MarshalPKCS1PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}

	// Get the public key
	publicKey := &privateKey.PublicKey
	ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	if err != nil {
		panic(err)
	}
	return
}
func (c *CryptoTools) RsaDecrypt(ciphertext []byte, privateKeyBytes []byte) (plaintext []byte) {
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	return
}

type message struct {
	Msg []byte `json:"msg"`
	Key []byte `json:"key"`
	Iv  []byte `json:"iv"`
}

type messageForRsa struct {
	Msg []byte `json:"msg"`
	Key []byte `json:"key"`
}
type messageEccsign struct {
	RText []byte `json:"rText"`
	SText []byte `json:"sText"`
	Msg   []byte `json:"msg"`
}

func (message *message) toString() string {
	return "msg: " + string(message.Msg) + "\n" +
		"key: " + string(message.Key) + "\n" +
		"iv: " + string(message.Iv) + "\n"
}
func makeMsg(plaintext []byte) message {
	ciphertext, key, iv := Ctools.AesCrypto(plaintext)
	msgJson := message{}
	msgJson.Msg = ciphertext
	msgJson.Key = key
	msgJson.Iv = iv
	return msgJson
}
func makeMsgForDes(plaintext []byte) message {
	ciphertext, key, iv := Ctools.DesCrypto(plaintext)
	msgJson := message{}
	msgJson.Msg = ciphertext
	msgJson.Key = key
	msgJson.Iv = iv
	return msgJson
}

func makeMsgForRsa(plaintext []byte) messageForRsa {
	ciphertext, key := Ctools.RsaCrypto(plaintext)
	msgJson := messageForRsa{}
	msgJson.Msg = ciphertext
	msgJson.Key = key
	return msgJson
}

func main() {
	//ecc
	eccerr := ecc.GenerateECCKey(256, "./")
	if eccerr != nil {
		fmt.Println(eccerr)
	}

	waitgrount := sync.WaitGroup{}
	waitgrount.Add(2)
	url := "ws://localhost:7777/ws"
	ws, err := websocket.Dial(url, "", "http://localhost/")
	if err != nil {
		log.Fatal(err)
	}
	go func(ws *websocket.Conn) {
		defer waitgrount.Done()

		for {
			reader := bufio.NewReader(os.Stdin)
			msg := make([]byte, 10000)

			var n int
			n, err = reader.Read(msg)
			if err != nil {
				log.Fatal(err)
			}

			//Aes
			//msgJson := makeMsg(msg[:n])

			//RSA
			//msgJson := makeMsgForRsa(msg[:n])
			//crytext, e := json.Marshal(msgJson)
			//if e != nil {
			//	log.Fatal(e)
			//}
			//ecc en
			//crytext, _ := ecc.EccEncrypt(msg[:n], "./eccPublic.pem")

			//ecc sign
			//rText, sText, _ := ecc.ECCSign(msg[:n], "./eccPrivate.pem")
			//var signMsg = messageEccsign{}
			//signMsg.SText = sText
			//signMsg.RText = rText
			//signMsg.Msg = msg[:n]
			//crytext, _ := json.Marshal(signMsg)
			//_, err := ws.Write(crytext)

			//des
			crytext, _, _ := Ctools.DesCrypto(msg[:n])
			_, err := ws.Write(crytext)

			if err == io.EOF {
				break
			}
		}

	}(ws)
	go func(ws *websocket.Conn) {
		defer waitgrount.Done()

		msg := make([]byte, 10000)
		for {
			n, _ := ws.Read(msg)

			//AES
			//var plaintextStruct message = message{}
			//RSA
			//var plaintextStruct = messageForRsa{}
			//
			//errUnmarshal := json.Unmarshal(msg[0:n], &plaintextStruct)
			//if errUnmarshal != nil {
			//	log.Fatal(errUnmarshal)
			//}

			//DES

			plaintext := Ctools.DesDecrypt(msg[0:n], []byte{}, []byte{})
			//AES
			//
			//plaintext := Ctools.AesDecrypt(plaintextStruct.Msg, plaintextStruct.Key, plaintextStruct.Iv)
			//
			////RSA
			//plaintext := Ctools.RsaDecrypt(plaintextStruct.Msg, plaintextStruct.Key)

			//ecc
			//plaintext, _ := ecc.EccDecrypt(msg[0:n], "./eccPrivate.pem")
			//ecc signed
			//var plaintextStruct messageEccsign = messageEccsign{}
			//json.Unmarshal(msg[0:n], &plaintextStruct)
			//ok, _ := ecc.ECCVerify(plaintextStruct.Msg, plaintextStruct.RText, plaintextStruct.SText, "./eccPublic.pem")
			//fmt.Printf("验证成功？ %t\n", ok)
			//if err == io.EOF {
			//	break
			//}
			//if err != nil {
			//	log.Fatal(err)
			//	break
			//}
			fmt.Print(string(plaintext))
		}
	}(ws)
	waitgrount.Wait()
}
