package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	flag "github.com/pborman/getopt"
)

type AESForm struct {
	state int
	sign int
	key []byte
	iv []byte
	masked_iv []byte
	mask []byte
	file []byte
}


func (a *AESForm) Decrypt() error {
	if a.sign != 0 {
		if a.mask == nil {
			a.iv = a.file[128:128 + aes.BlockSize]
		} else {
			iv, err := IVFromMask(a.mask, a.file[a.sign:a.sign + aes.BlockSize])
			if err != nil {
				return fmt.Errorf("Decrypt: failed generating IV: %w", err)
			} else {
				a.iv = iv
			}
		}
	} else {
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
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return fmt.Errorf("Decrypt: failed creating cipher: %w", err)
	}

	if len(a.file) < aes.BlockSize {
		return fmt.Errorf("Decrypt: ciphertext is too short")
	}

	var ciphertext []byte

	if a.sign != 0 {
		ciphertext = a.file[aes.BlockSize + a.sign:]
	} else {
		ciphertext = a.file[aes.BlockSize:]
	}

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
	if a.sign != 0 {
		a.file = []byte(string(a.file[:a.sign]) + string(a.masked_iv) + string(a.file))
	} else {
		a.file = []byte(string(a.masked_iv) + string(a.file))
	}
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
func New(state int, sign int, path string, key string, iv string, mask string) (AESForm, error) {
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
	par.sign = sign

	return par, nil
}

func main() {
	var (
		help = false
		state = -1
		sign = 0
		key = ""
		input = ""
		output = "~/out.bin"
		mask = ""
		iv = ""
	)
	
	flag.BoolVarLong(&help, "help", 'h', "displays help")
	flag.IntVarLong(&state, "state", 's', "Whether the data is encrypted (0) or decrypted (1)", "int")
	flag.IntVarLong(&sign, "index", 'n', "Index of data encrypted with sign", "int")
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

	a, err := New(state, sign, input, key, iv, mask)
	if err != nil {
		log.Fatalf("main: failed parsing data: %s", err)
	} else {
		switch a.state {
		case 0:
			err = a.Decrypt()
			if err != nil {
				log.Fatalf("main: failed decrypting data: %s", err)
			} else {
				log.Print("Successfully decrypted file...")
			}
		case 1:
			err = a.Encrypt()
			if err != nil {
				log.Fatalf("main: failed encrypting data: %s", err)
			} else {
				log.Print("Successfully encrypted file...")
			}
		default:
			log.Fatal("main: invalid state!")
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


// If you are using this to decrypt Arknights data, then the below function
// can be used to convert BSON data to JSON for viewability, make sure to set the sign to 128.

// func (a *AESForm) TestMarshal() error {
// 	var raw bson.Raw = a.file[:len(a.file) - 8]
// 	mp := make(map[string]interface{})
// 	err := bson.Unmarshal(raw, &mp)
// 	if err != nil {
// 		return fmt.Errorf("TestMarshal: failed unmarshalling bson: %w", err)
// 	}
// 	data, err := json.Marshal(mp)
// 	if err != nil {
// 		return fmt.Errorf("TestMarshal: failed marshalling to json: %w", err)
// 	}
// 	a.file = data
// 	return nil
// }

// func (a *AESForm) TestUnmarshal() error {
// 	mp := make(map[string]interface{})
// 	err := json.Unmarshal(a.file, &mp)
// 	if err != nil {
// 		return fmt.Errorf("TestUnmarshal: failed unmarshalling json: %w", err)
// 	}
// 	data, err := bson.Marshal(mp)
// 	if err != nil {
// 		return fmt.Errorf("TestUnmarshal: failed marshalling to bson: %w", err)
// 	}
// 	a.file = data
// 	return nil
// }