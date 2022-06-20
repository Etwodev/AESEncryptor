# AESEncryptor
Simple AES CBC Encryption example

## Installation
You can install the binary with:
```sh
go install github.com/Etwodev/AESEncryptor@latest
```
Or install the library with:
```sh
go get github.com/Etwodev/AESEncryptor@latest
```


## Usage
The following command will decrypt the file 'random.bytes' with the key '554954704169383270484157776E7A71' and mask '48524D4377506F6E4A4C49423357436C'
In this case, the 's' value is 0, meaning the inputted data is encrypted, to be decrypted.
```sh
~/go/bin/AESEncryptor -i './random.bytes' -o './out.bin' -k '554954704169383270484157776E7A71' -m '48524D4377506F6E4A4C49423357436C' -s 0
```

On the reverse, we can reencrypt the file we just decrypted, like so:
```sh
~/go/bin/AESEncryptor -i './out.bin' -o './reencrypt.bytes' -k '554954704169383270484157776E7A71' -m '48524D4377506F6E4A4C49423357436C' -s 1
```

If you want to just encrypt a file from no mask, you can do the following:
```sh
~/go/bin/AESEncryptor -i './out.bin' -o './encrypted.bytes' -k '554954704169383270484157776E7A71' -s 1
```

```sh
user@some_local_user ~ % ~/go/bin/AESEncryptor -h
Usage: AESEncryptor [-h] [-i str] [-k str] [-m str] [-o str] [-s int] [-v str] [parameters ...]
 -h, --help        displays help
 -i, --input=str   The input file
 -k, --key=str     The input file
 -m, --mask=str    The AES mask in hexadecimal (Optional)
 -o, --output=str  The output file path
 -s, --state=int   Whether the data is encrypted (0) or decrypted (1)
 -v, --vect=str    The AES init vector in hexadecimal (Optional)
 ```
