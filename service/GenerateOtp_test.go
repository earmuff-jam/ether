package service

import (
	"errors"
	"testing"

	"github.com/earmuff-jam/ether/types"
	"github.com/earmuff-jam/ether/utils"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_prefixValue(t *testing.T) {
	resp := prefix("0", "abc")

	assert.Len(t, resp, 6)
	assert.Equal(t, resp, "000abc")

	resp = prefix("0", "ABZ123")

	assert.Len(t, resp, 6)
	assert.Equal(t, resp, "ABZ123")
}

func Test_GenerateOtp_Valid(t *testing.T) {

	draftOtp := &types.OTPCredentials{
		EmailAddress:  "test@gmail.com",
		Token:         "dummy-secret-key",
		UserID:        uuid.New(),
		TokenValidity: 10, // in seconds
	}

	resp, err := GenerateOneTimePassword(draftOtp)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func Test_GenerateOtp_InvalidOtpCredentialValues(t *testing.T) {
	draftOtp := &types.OTPCredentials{
		Token:         "dummy-secret-key",
		UserID:        uuid.New(),
		TokenValidity: 10, // in seconds
	}

	_, err := GenerateOneTimePassword(draftOtp)

	assert.Error(t, err)
	assert.Equal(t, err, errors.New(utils.ErrorGeneratingOTP))

	draftOtp = &types.OTPCredentials{
		EmailAddress:  "test@gmail.com",
		UserID:        uuid.New(),
		TokenValidity: 10, // in seconds
	}

	_, err = GenerateOneTimePassword(draftOtp)

	assert.Error(t, err)
	assert.Equal(t, err, errors.New(utils.ErrorGeneratingOTP))

	draftOtp = &types.OTPCredentials{
		EmailAddress:  "test@gmail.com",
		Token:         "dummy-secret-key",
		TokenValidity: 10, // in seconds
	}

	_, err = GenerateOneTimePassword(draftOtp)

	assert.Error(t, err)
	assert.Equal(t, err, errors.New(utils.ErrorGeneratingOTP))

	draftOtp = &types.OTPCredentials{
		EmailAddress: "test@gmail.com",
		Token:        "dummy-secret-key",
		UserID:       uuid.New(),
	}

	// no error for missing token validity time
	resp, err := GenerateOneTimePassword(draftOtp)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp)
}
