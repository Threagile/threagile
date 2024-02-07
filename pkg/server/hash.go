/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package server

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/fnv"
)

func xor(key []byte, xor []byte) []byte {
	if len(key) != len(xor) {
		panic(fmt.Errorf("key length not matching XOR length"))
	}
	result := make([]byte, len(xor))
	for i, b := range key {
		result[i] = b ^ xor[i]
	}
	return result
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}
