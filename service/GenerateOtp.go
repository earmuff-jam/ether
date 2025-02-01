package service

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"earmuff-jam/ether/types"
	"earmuff-jam/ether/utils"
	"encoding/binary"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// GenerateOneTimePassword ...
//
// function that takes in a struct of credentials with a unique
// identifier for each user and creates a valid OTP for the user
// to use in the application. token validity can be passed in
// the function or default value can be used.
func GenerateOneTimePassword(otp *types.OTPCredentials) (string, error) {

	if len(otp.EmailAddress) <= 0 {
		log.Printf("invalid user email address")
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	if _, err := uuid.Parse(otp.UserID.String()); err != nil {
		log.Printf("invalid uuid detected")
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	if otp.UserID == uuid.Nil {
		log.Printf("invalid uuid detected")
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	if len(otp.Token) <= 0 {
		log.Printf("missing token key")
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	tokenValidity := otp.TokenValidity

	if otp.TokenValidity <= 0 {
		// default validity of token is 5 mins
		log.Printf("invalid token validity time. using default")
		tokenValidity = utils.DefaultIntervalTime
	}

	interval := time.Now().Unix() / int64(tokenValidity)

	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	// generates unique key per email address
	combinedKey := otp.Token + otp.UserID.String()

	genKeys, err := generateHMACKeys([]byte(combinedKey), bs)
	if err != nil {
		log.Printf("unable to generate HMAC keys")
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	return genKeys, nil
}

// generateHMACKeys ...
//
// function is used to generateHMACKeys
func generateHMACKeys(key, message []byte) (string, error) {

	hashKeys := hmac.New(sha1.New, key)

	hashKeys.Write(message)
	hashKeysSum := hashKeys.Sum(nil)

	// Use a subset of the generated hash.
	subsetNibble := (hashKeysSum[19] & 15)
	var header uint32
	response := bytes.NewReader(hashKeysSum[subsetNibble : subsetNibble+4])
	err := binary.Read(response, binary.BigEndian, &header)
	if err != nil {
		log.Printf("unable to decode provide subset. error: %+v", err)
		return "", err
	}
	// ignore significant bits; generate a remainder less than 7 digits
	hmacKey := (int(header) & 0x7fffffff) % 1000000
	otp := strconv.Itoa(hmacKey)

	return prefix("0", otp), nil
}

// prefix ...
//
// function is used to prefix the string with if the length is less
// than six digits
func prefix(prefixVal string, optStr string) string {
	if len(optStr) == 6 {
		return optStr
	}
	for i := (6 - len(optStr)); i > 0; i-- {
		optStr = prefixVal + optStr
	}
	return optStr
}
