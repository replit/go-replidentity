package repl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalUnmarshalUserId(t *testing.T) {
	testMarshalUnmarshal := func(u *UserId) {
		out, err := u.MarshalText()
		require.NoError(t, err)
		exp := UserId{}
		err = exp.UnmarshalText(out)
		require.NoError(t, err)
		require.Equal(t, u.GetId(), exp.GetId())
		require.Equal(t, u.GetEnvironment(), exp.GetEnvironment())
	}

	testMarshalUnmarshal(nil)
	testMarshalUnmarshal(&UserId{})
	testMarshalUnmarshal(&UserId{
		Id:          777,
		Environment: Environment_DEVELOPMENT,
	})
	testMarshalUnmarshal(&UserId{
		Id:          123456,
		Environment: Environment_PRODUCTION,
	})
}
