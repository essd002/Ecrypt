/*
Ecrypt v1.0 made by E$$D
Powered by Kyouno Lab Incorporated
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/gotk3/gotk3/gtk"
	"io"
	"io/ioutil"
	"log"
)

func main() {
	var fl bool
	gtk.Init(nil) //Gtk init

	b, err := gtk.BuilderNew() // Init new builder
	if err != nil {
		log.Fatal("Ошибка:", err)
	}
	err = b.AddFromFile("layout.glade") // Open Layout
	if err != nil {
		log.Fatal("Ошибка:", err)
	}
	obj, err := b.GetObject("window") // Get object from layout
	if err != nil {
		log.Fatal("Ошибка:", err)
	}
	win := obj.(*gtk.Window)
	win.Connect("destroy", func() {
		gtk.MainQuit()
	})
	obj, _ = b.GetObject("encrypt") // Get string entry
	encrypt := obj.(*gtk.Entry)

	obj, _ = b.GetObject("pass") // Get password entry
	passwd := obj.(*gtk.Entry)

	obj, _ = b.GetObject("enc") // Get encrypt button
	enc_button := obj.(*gtk.Button)

	obj, _ = b.GetObject("dec") // Get decrypt button
	dec_button := obj.(*gtk.Button)

	obj, _ = b.GetObject("out") // Get label for errors output
	lout := obj.(*gtk.Label)

	obj, _ = b.GetObject("file") // Get label for errors output
	file_ := obj.(*gtk.CheckButton)

	win.ShowAll() // Show all widgets

	file_.Connect("clicked", func() { // Connect to encrypt button
		fl = file_.GetActive()
	})

	enc_button.Connect("clicked", func() { // Connect to encrypt button
		lout.SetText("")
		text, err := encrypt.GetText()
		password, err := passwd.GetText()
		if fl {
			data, err := ioutil.ReadFile(text)
			if err != nil {
				lout.SetText(err.Error())
			} else {
				data, err := e_crypt(string(data), password)
				if err != nil {
					lout.SetText(err.Error())
				} else {
					err := ioutil.WriteFile(text, []byte(data), 0644)
					if err != nil {
						lout.SetText(err.Error())
					} else {
						lout.SetText("Done")
					}
				}
			}
		} else {
			if err == nil {
				out, err := e_crypt(text, password)
				if err != nil {
					lout.SetText(err.Error())
				}
				encrypt.SetText(out)
				//lout.SetText(out)
			}
		}
	})

	dec_button.Connect("clicked", func() { // Connect to decrypt button
		lout.SetText("")
		text, err := encrypt.GetText()
		password, err := passwd.GetText()
		if fl {
			// file, err := os.Create(text)
			data, err := ioutil.ReadFile(text)
			if err != nil {
				lout.SetText(err.Error())
			} else {
				data, err := e_dcrypt(string(data), password)
				if err != nil {
					lout.SetText(err.Error())
				} else {
					err := ioutil.WriteFile(text, []byte(data), 0644)
					if err != nil {
						lout.SetText(err.Error())
					} else {
						lout.SetText("Done")
					}
				}
			}
		} else {
			if err == nil {
				out, err := e_dcrypt(text, password)
				//lout.SetText(out)
				if err != nil {
					lout.SetText(err.Error())
				}
				encrypt.SetText(out)
			}
		}
	})
	gtk.Main()
}

func decryptString(cryptoText string, keyString string) (plainTextString string, err error) {

	newKeyString, err := hashTo32Bytes(keyString) // Format the keyString so that it's 32 bytes.

	cipherText, _ := base64.URLEncoding.DecodeString(cryptoText) // Encode the cryptoText to base 64.

	block, err := aes.NewCipher([]byte(newKeyString))

	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		return "", errors.New("Cant decode")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

func encryptString(plainText string, keyString string) (cipherTextString string, err error) {

	newKeyString, err := hashTo32Bytes(keyString) // Format the keyString so that it's 32 bytes.

	if err != nil {
		return "", err
	}

	key := []byte(newKeyString)
	value := []byte(plainText)

	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(value))

	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText[aes.BlockSize:], value)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func hashTo32Bytes(input string) (output string, err error) { // Cut the length down to 32 bytes

	if len(input) == 0 {
		return "", errors.New("No input supplied")
	}

	hasher := sha256.New()
	hasher.Write([]byte(input))

	stringToSHA256 := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return stringToSHA256[:32], nil
}

func e_crypt(str string, key string) (out string, err error) { // special encrypt algorithm
	rkey := Reverse(key)
	a, err := encryptString(str, key)
	if err != nil {
		return "", err
	}
	renc := Reverse(a)
	a, err = encryptString(renc, rkey)
	if err != nil {
		return "", err
	}
	return a, nil
}

func e_dcrypt(str string, key string) (out string, err error) { // special decrypt algorithm
	rkey := Reverse(key)
	a, err := decryptString(str, rkey)
	if err != nil {
		return "", err
	}
	renc := Reverse(a)
	a, err = decryptString(renc, key)
	if err != nil {
		return "", err
	}
	return a, nil
}
