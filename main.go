package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"log"
	flag "github.com/pborman/getopt"
)

type AESForm struct {
	state int
	key []byte
	iv []byte
	masked_iv []byte
	mask []byte
	file []byte
}


func (a *AESForm) Decrypt() error {
	if a.mask == nil {
		a.iv = a.file[:aes.BlockSize]
	} else {
		iv, err := IVFromMask(a.mask, a.file[:aes.BlockSize])
		if err != nil {
			return fmt.Errorf("Decrypt: failed generating IV: %w", err)
		} else {
			a.iv = iv
		}
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return fmt.Errorf("Decrypt: failed creating cipher: %w", err)
	}

	if len(a.file) < aes.BlockSize {
		return fmt.Errorf("Decrypt: ciphertext is too short")
	}

	ciphertext := a.file[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return fmt.Errorf("Decrypt: ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, a.iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	a.file = ciphertext
	a.state = 1
	return nil
}

func IVFromMask(mask []byte, block []byte) ([]byte, error) {
	var buff []byte

	if len(mask) != len(block) {
		return nil, fmt.Errorf("IVFromMask: mask size mismatch")
	}

	for i, v := range block {
		buff = append(buff, mask[i]^v)
	}
	return buff, nil
}

func (a *AESForm) Encrypt() error {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return fmt.Errorf("Encrypt: failed creating cipher: %w", err)
	}

	if len(a.file)%aes.BlockSize != 0 {
		return fmt.Errorf("Encrypt: item is not a multiple of the block size")
    }

	if a.mask != nil {
		a.masked_iv, err = IVFromMask(a.mask, a.iv)
		if err != nil {
			return fmt.Errorf("Encrypt: failed masking iv: %w", err)
		}
	} else {
		a.masked_iv = a.iv
	}

	mode := cipher.NewCBCEncrypter(block, a.iv)
	mode.CryptBlocks(a.file, a.file)
	a.file = []byte(string(a.masked_iv) + string(a.file))
	a.state = 0
	return nil
}

// New() expects strings formatted in hex for the following values:
// key string -> hex.DecodeString -> []byte
// iv string -> hex.DecodeString -> []byte
// mask string -> hex.DecodeString -> []byte
// States: 
// 0 (Encrypted) -> Decrypt
// 1 (Decrypted) -> Encrypt
// Where path is the path of the file to be read
func New(state int, path string, key string, iv string, mask string) (AESForm, error) {
	var par AESForm

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return par, fmt.Errorf("New: failed reading file: %w", err)
	} else {
		par.file = file
	}

	if mask != "" {
		bMask, err := hex.DecodeString(mask)
		if err != nil {
			return par, fmt.Errorf("New: failed decoding hex: %w", err)
		} else {
			par.mask = bMask
		}
	}

	if iv != "" {
		bIV, err := hex.DecodeString(iv)
		if err != nil || len(bIV) != aes.BlockSize {
			return par, fmt.Errorf("New: failed decoding hex: %w", err)
		} else {
			par.iv = bIV
		}
	} else {
		bytes := make([]byte, aes.BlockSize)
		if _, err := rand.Read(bytes); err != nil {
		  log.Fatalf("New: failed generating bytes: %s", err)
		}
		par.iv = bytes
	}

	bKey, err := hex.DecodeString(key)
	if err != nil {
		return par, fmt.Errorf("New: failed decoding hex: %w", err)
	} 

	par.state = state
	par.key = bKey

	return par, nil
}

func main() {
	var (
		help = false
		state = -1
		key = ""
		input = ""
		output = "~/out.bin"
		mask = ""
		iv = ""
	)
	
	flag.BoolVarLong(&help, "help", 'h', "displays help")
	flag.IntVarLong(&state, "state", 's', "Whether the data is encrypted (0) or decrypted (1)", "int")
	flag.StringVarLong(&key, "key", 'k', "The input file", "str")
	flag.StringVarLong(&input, "input", 'i', "The input file", "str")
	flag.StringVarLong(&output, "output", 'o', "The output file path", "str")
	flag.StringVarLong(&mask, "mask", 'm', "The AES mask in hexadecimal (Optional)", "str")
	flag.StringVarLong(&iv, "vect", 'v', "The AES init vector in hexadecimal (Optional)", "str")

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	log.Printf("Key: '%s'", key)
	log.Printf("Mask: '%s'", mask)
	log.Printf("IV: '%s'", iv)
	log.Printf("State: %s", fmt.Sprint(state))
	log.Printf("In: '%s'", input)
	log.Printf("Out: '%s'", output)

	if key == "" {
		log.Fatal("main: missing key!")
	}

	if state == -1 {
		log.Fatal("main: please specify state!")
	}

	if input == "" {
		log.Fatal("main: output file required")
	}

	a, err := New(state, input, key, iv, mask)
	if err != nil {
		log.Fatalf("main: failed parsing data: %s", err)
	} else {
		if a.state == 0 {
			err = a.Decrypt()
			if err != nil {
				log.Fatalf("main: failed decrypting data: %s", err)
			} else {
				log.Print("Successfully decrypted file...")
			}
		} else {
			err = a.Encrypt()
			if err != nil {
				log.Fatalf("main: failed encrypting data: %s", err)
			} else {
				log.Print("Successfully encrypted file...")
			}
		}
	}

	out, err := os.Create(output)
	if err != nil  {
		log.Fatalf("main: failed creating file: %s", err)
	}
	defer out.Close()

	_, err = out.Write(a.file)
	if err != nil {
		log.Fatalf("main: failed writing file: %s", err)
	}	
}