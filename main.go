package ether

import (
	"errors"

	"github.com/earmuff-jam/ether/service"
	"github.com/earmuff-jam/ether/types"
	"github.com/earmuff-jam/ether/utils"
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
