package ether

import (
	"earmuff-jam/ether/service"
	"earmuff-jam/ether/types"
	"earmuff-jam/ether/utils"
	"errors"
)

// GenerateOTP ...
//
// Generates OTP token
func GenerateOTP(optCreds *types.OTPCredentials) (string, error) {

	if len(optCreds.EmailAddress) <= 0 {
		return "", errors.New(utils.ErrorInvalidEmailAddress)
	}

	passKey, err := service.GenerateOneTimePassword(optCreds)
	if err != nil {
		return "", errors.New(utils.ErrorGeneratingOTP)
	}

	return passKey, nil
}
