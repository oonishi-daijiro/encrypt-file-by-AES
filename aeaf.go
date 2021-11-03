package main

import (
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

type args struct {
	input      string
	key    string
	mode   string
	argArr []string
}

type progress struct {
	max        int
	contentMax int
}

func (p progress) rendBar(now *int) {
	go func() {
		for {
			realtive := (p.max * *now) / p.contentMax
			bar := strings.Repeat("=", realtive)
			gopher := strings.Repeat("ʕ◔ϖ◔ʔ", len(bar)/10)
			bar += ">"
			remain := strings.Repeat(" ", p.max-realtive)
			if realtive == p.max {
				fmt.Print("[", bar, remain, "]", "\n")
				break
			}
			fmt.Print("[", bar, remain, "]", gopher, "\r")
			time.Sleep(time.Second)
		}
	}()
}

var red *color.Color = color.New(color.FgRed).Add(color.Underline)
var blue *color.Color = color.New(color.FgBlue).Add(color.Underline)

// encrypting and decrypting by sequential proccess
func main() {
	cmdArgs, err := newArgs()
	if err != nil {
		red.Print("error: ")
		fmt.Println(err.Error())
		return
	}
	if len(cmdArgs.argArr) != 0 {
		fmt.Println("Syntax of argument is incorrect")
		return
	}
	inputedKey := cmdArgs.key
	if inputedKey == "" {
		red.Print("Error :")
		fmt.Println("Please set value of key.")
		return
	}
	switch cmdArgs.mode {
	case "enc":
		blue.Println("Encrypting...")
		encryptedFile,err := encryption(inputedKey, cmdArgs.input)
		if err != nil {
			red.Print("Error :")
			fmt.Println(err.Error())
			return
		}
		writeToFile(cmdArgs.input, encryptedFile)
		blue.Println("\nDone!!  ʕ◔ϖ◔ʔ")
		return
	case "dec":
		inputFile, err := ioutil.ReadFile(cmdArgs.input)
		blue.Println("Decrypting...")
		if err != nil {
			red.Print("error: ")
			fmt.Println(err.Error())
			return
		}
		decrypted, err := decryption(inputedKey, &inputFile)
		if err != nil {
			red.Print("error: ")
			fmt.Println(err.Error())
			return
		}
		writeToFile(cmdArgs.input, decrypted)
		blue.Println("\nDone ʕ◔ϖ◔ʔ")
	default:
		fmt.Println("Please set argument \"dec\" or \"enc\"")
		return
	}
}

func newArgs() (*args, error) {
	cmdArg := new(args)
	encSub := flag.NewFlagSet("enc", flag.ExitOnError)
	decSub := flag.NewFlagSet("dec", flag.ExitOnError)
	if len(os.Args) == 1 {
		lessArgErr := errors.New("Please set argument")
		return nil, lessArgErr
	}
	switch os.Args[1] {
	case "enc":
		i, key := setSubflag(encSub)
		cmdArg.input = i
		cmdArg.key = key
		cmdArg.mode = "enc"
	case "dec":
		i, key := setSubflag(decSub)
		cmdArg.input = i
		cmdArg.key = key
		cmdArg.mode = "dec"
	default:
		err := errors.New("Please set subcommand \"enc\" or \"dec\"")
		return nil, err
	}
	cmdArg.argArr = flag.Args()
	return cmdArg, nil
}

func setSubflag(subset *flag.FlagSet) (string, string) {
	i := subset.String("i", "", "Path of input file")
	key := subset.String("key", "", "Key of encrypt and decrypt")
	subset.Parse(os.Args[2:])
	return *i, *key
}

func encryption(password string, path string) (*[]uint8,error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		red.Print("Error: ")
		fmt.Println(err.Error())
		return nil, err
	}
	hash := createHash(password)
	paded := paddingBlock16(&file)
	times := len(paded) / aes.BlockSize
	progressBar := new(progress)
	progressBar.contentMax = times
	progressBar.max = 60
	var i int
	progressBar.rendBar(&i)
	for i = 0; i < times; i++ {
		start := i * aes.BlockSize
		end := start + aes.BlockSize
		cipherPart := createCipher(hash, paded[start:end])
		replace(&paded, &cipherPart, start)
	}
	return &paded,nil
}

func writeToFile(path string, file *[]uint8) {
	createdFile, err := os.Create(path)
	if err != nil {
		red.Print("error: ")
		fmt.Println(err.Error())
	}
	createdFile.Write(*file)
}

func createCipher(key [32]uint8, plain []uint8) []uint8 {
	slice := key[:]
	aesEnc, err := aes.NewCipher(slice)
	if err != nil {
		red.Print("Error: ")
		fmt.Println(err.Error())
	}
	ciphered := make([]byte, 16)
	aesEnc.Encrypt(ciphered, plain)
	return ciphered
}

func decryption(key string, ciphered *[]uint8) (*[]uint8, error) {
	hash := createHash(key)
	slice := hash[:]
	aesDec, err := aes.NewCipher(slice)
	if err != nil {
		red.Print("Error: ")
		fmt.Println(err.Error())
		return nil, err
	}
	// allOfPlain := make([]uint8, len(*ciphered))
	times := len(*ciphered) / aes.BlockSize
	progressBar := new(progress)
	progressBar.max = 60
	progressBar.contentMax = times
	var i int
	progressBar.rendBar(&i)
	for i = 0; i < times; i++ {
		plainParts := make([]uint8, aes.BlockSize)
		start := i * aes.BlockSize
		end := start + aes.BlockSize
		aesDec.Decrypt(plainParts, (*ciphered)[start:end])
		replace(ciphered, &plainParts, start)
	}
	isInRange := 0 < ((*ciphered)[len(*ciphered)-1]) && ((*ciphered)[len(*ciphered)-1] <= 16)
	if !isInRange {
		err := errors.New("Cannot decrypt this file")
		return nil, err
	}
	parsePad(ciphered) // parseing padding by pointer
	return ciphered, nil
}

func parsePad(decrypted *[]uint8) {
	pads := (*decrypted)[(len(*decrypted))-1]
	intPads := int(pads)
	*decrypted = (*decrypted)[0 : len(*decrypted)-intPads]
}

func replace(targetArr *[]uint8, content *[]uint8, startAt int) {
	for i := range *content {
		(*targetArr)[startAt+i] = (*content)[i]
	}
}

func paddingBlock16(content *[]uint8) []uint8 {
	times := getNumOfCalcing(len(*content), aes.BlockSize)
	size := (times) * 16
	if (size - len(*content)) == 0 {
		size = (times + 1) * 16
	}
	pad := size - len(*content)
	prototype := make([]uint8, size)
	replace(&prototype, content, 0)
	for i := 1; i <= pad; i++ {
		prototype[len(prototype)-i] = uint8(pad)
	}
	return prototype
}

func createHash(plain string) [32]uint8 {
	hoge := []byte(plain)
	hash := sha256.Sum256(hoge)
	return hash
}

func getNumOfCalcing(length int, blocksize int) int {
	over := length % blocksize
	trimed := length - over
	times := trimed / blocksize
	if over != 0 {
		times++
	}
	return times
}
