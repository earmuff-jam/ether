package ether

import (
	"testing"

	"github.com/earmuff-jam/ether/types"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func Test_GenerateOtp(t *testing.T) {

	draftOtp := types.OTPCredentials{
		UserID:        uuid.New(),
		EmailAddress:  "test@gmail.com",
		TokenValidity: 10,
		Token:         "dummy-token-key",
	}

	resp, err := GenerateOTP(&draftOtp)

	assert.NoError(t, err)
	assert.Equal(t, len(resp), 6)

}

func Test_GenerateOtpFailures(t *testing.T) {
	draftOtp := types.OTPCredentials{
		UserID:        uuid.New(),
		TokenValidity: 10,
		Token:         "dummy-token-key",
	}

	resp, err := GenerateOTP(&draftOtp)

	assert.Error(t, err)
	assert.Equal(t, len(resp), 0)

	draftOtp = types.OTPCredentials{
		EmailAddress:  "test@gmail.com",
		TokenValidity: 10,
		Token:         "dummy-token-key",
	}

	resp, err = GenerateOTP(&draftOtp)

	assert.Error(t, err)
	assert.Equal(t, len(resp), 0)
}
