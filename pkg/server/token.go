/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const keySize = 32

type keyHeader struct {
	Key string `header:"key"`
}

type timeoutStruct struct {
	xorRand                               []byte
	createdNanoTime, lastAccessedNanoTime int64
}

func (s *server) createKey(ginContext *gin.Context) {
	ok := s.checkObjectCreationThrottler(ginContext, "KEY")
	if !ok {
		return
	}
	s.globalLock.Lock()
	defer s.globalLock.Unlock()

	keyBytesArr := make([]byte, keySize)
	n, err := rand.Read(keyBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	err = os.MkdirAll(s.folderNameFromKey(keyBytesArr), 0700)
	if err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create key",
		})
		return
	}
	ginContext.JSON(http.StatusCreated, gin.H{
		"key": base64.RawURLEncoding.EncodeToString(keyBytesArr[:]),
	})
}

func (s *server) checkObjectCreationThrottler(ginContext *gin.Context, typeName string) bool {
	s.throttlerLock.Lock()
	defer s.throttlerLock.Unlock()

	// remove all elements older than 3 minutes (= 180000000000 ns)
	now := time.Now().UnixNano()
	cutoff := now - 180000000000
	for keyCheck := range s.createdObjectsThrottler {
		for i := 0; i < len(s.createdObjectsThrottler[keyCheck]); i++ {
			if s.createdObjectsThrottler[keyCheck][i] < cutoff {
				// Remove the element at index i from slice (safe while looping using i as iterator)
				s.createdObjectsThrottler[keyCheck] = append(s.createdObjectsThrottler[keyCheck][:i], s.createdObjectsThrottler[keyCheck][i+1:]...)
				i-- // Since we just deleted a[i], we must redo that index
			}
		}
		length := len(s.createdObjectsThrottler[keyCheck])
		if length == 0 {
			delete(s.createdObjectsThrottler, keyCheck)
		}
		/*
			if *verbose {
				log.Println("Throttling count: "+strconv.Itoa(length))
			}
		*/
	}

	// check current request
	keyHash := hash(typeName) // getting the real client ip is not easy inside fully encapsulated containerized runtime
	if _, ok := s.createdObjectsThrottler[keyHash]; !ok {
		s.createdObjectsThrottler[keyHash] = make([]int64, 0)
	}
	// check the limit of 20 creations for this type per 3 minutes
	withinLimit := len(s.createdObjectsThrottler[keyHash]) < 20
	if withinLimit {
		s.createdObjectsThrottler[keyHash] = append(s.createdObjectsThrottler[keyHash], now)
		return true
	}
	ginContext.JSON(http.StatusTooManyRequests, gin.H{
		"error": "object creation throttling exceeded (denial-of-service protection): please wait some time and try again",
	})
	return false
}

func (s *server) deleteKey(ginContext *gin.Context) {
	folderName, _, ok := s.checkKeyToFolderName(ginContext)
	if !ok {
		return
	}
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	err := os.RemoveAll(folderName)
	if err != nil {
		log.Println("error during key delete: " + err.Error())
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return
	}
	ginContext.JSON(http.StatusOK, gin.H{
		"message": "key deleted",
	})
}

func (s *server) createToken(ginContext *gin.Context) {
	folderName, key, ok := s.checkKeyToFolderName(ginContext)
	if !ok {
		return
	}
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	if tokenHash, exists := s.mapFolderNameToTokenHash[folderName]; exists {
		// invalidate previous token
		delete(s.mapTokenHashToTimeoutStruct, tokenHash)
	}
	// create a strong random 256 bit value (used to xor)
	xorBytesArr := make([]byte, keySize)
	n, err := rand.Read(xorBytesArr[:])
	if n != keySize || err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create token",
		})
		return
	}
	now := time.Now().UnixNano()
	token := xor(key, xorBytesArr)
	tokenHash := hashSHA256(token)
	s.housekeepingTokenMaps()
	s.mapTokenHashToTimeoutStruct[tokenHash] = timeoutStruct{
		xorRand:              xorBytesArr,
		createdNanoTime:      now,
		lastAccessedNanoTime: now,
	}
	s.mapFolderNameToTokenHash[folderName] = tokenHash
	ginContext.JSON(http.StatusCreated, gin.H{
		"token": base64.RawURLEncoding.EncodeToString(token[:]),
	})
}

type tokenHeader struct {
	Token string `header:"token"`
}

func (s *server) deleteToken(ginContext *gin.Context) {
	header := tokenHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return
	}
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	s.deleteTokenHashFromMaps(hashSHA256(token))
	ginContext.JSON(http.StatusOK, gin.H{
		"message": "token deleted",
	})
}

func (s *server) checkKeyToFolderName(ginContext *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := keyHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Key))
	if len(key) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	folderNameOfKey = s.folderNameFromKey(key)
	if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "key not found",
		})
		return folderNameOfKey, key, false
	}
	return folderNameOfKey, key, true
}

func (s *server) checkTokenToFolderName(ginContext *gin.Context) (folderNameOfKey string, key []byte, ok bool) {
	header := tokenHeader{}
	if err := ginContext.ShouldBindHeader(&header); err != nil {
		log.Println(err)
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(header.Token))
	if len(token) == 0 || err != nil {
		if err != nil {
			log.Println(err)
		}
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
	s.globalLock.Lock()
	defer s.globalLock.Unlock()
	s.housekeepingTokenMaps() // to remove timed-out ones
	tokenHash := hashSHA256(token)
	if timeoutStruct, exists := s.mapTokenHashToTimeoutStruct[tokenHash]; exists {
		// re-create the key from token
		key := xor(token, timeoutStruct.xorRand)
		folderNameOfKey := s.folderNameFromKey(key)
		if _, err := os.Stat(folderNameOfKey); os.IsNotExist(err) {
			log.Println(err)
			ginContext.JSON(http.StatusNotFound, gin.H{
				"error": "token not found",
			})
			return folderNameOfKey, key, false
		}
		timeoutStruct.lastAccessedNanoTime = time.Now().UnixNano()
		return folderNameOfKey, key, true
	} else {
		ginContext.JSON(http.StatusNotFound, gin.H{
			"error": "token not found",
		})
		return folderNameOfKey, key, false
	}
}

func (s *server) folderNameFromKey(key []byte) string {
	sha512Hash := hashSHA256(key)
	return filepath.Join(s.config.ServerFolder, s.config.KeyFolder, sha512Hash)
}

func (s *server) housekeepingTokenMaps() {
	now := time.Now().UnixNano()
	for tokenHash, val := range s.mapTokenHashToTimeoutStruct {
		if s.extremeShortTimeoutsForTesting {
			// remove all elements older than 1 minute (= 60000000000 ns) soft
			// and all elements older than 3 minutes (= 180000000000 ns) hard
			if now-val.lastAccessedNanoTime > 60000000000 || now-val.createdNanoTime > 180000000000 {
				fmt.Println("About to remove a token hash from maps")
				s.deleteTokenHashFromMaps(tokenHash)
			}
		} else {
			// remove all elements older than 30 minutes (= 1800000000000 ns) soft
			// and all elements older than 10 hours (= 36000000000000 ns) hard
			if now-val.lastAccessedNanoTime > 1800000000000 || now-val.createdNanoTime > 36000000000000 {
				s.deleteTokenHashFromMaps(tokenHash)
			}
		}
	}
}

func (s *server) deleteTokenHashFromMaps(tokenHash string) {
	delete(s.mapTokenHashToTimeoutStruct, tokenHash)
	for folderName, check := range s.mapFolderNameToTokenHash {
		if check == tokenHash {
			delete(s.mapFolderNameToTokenHash, folderName)
			break
		}
	}
}
