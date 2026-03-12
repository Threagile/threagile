package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBuiltIn_Known(t *testing.T) {
	assert.True(t, IsBuiltIn("calculate_severity"))
}

func TestIsBuiltIn_Unknown(t *testing.T) {
	assert.False(t, IsBuiltIn("unknown"))
}

func TestCallBuiltIn_CalculateSeverity(t *testing.T) {
	// unlikely=0 (weight 1), low=0 (weight 1) => 1*1=1 => LowSeverity => "low"
	unlikelyVal := SomeStringValue("unlikely", nil)
	lowVal := SomeStringValue("low", nil)

	result, err := CallBuiltIn("calculate_severity", unlikelyVal, lowVal)
	assert.NoError(t, err)
	assert.Equal(t, "low", result.Value())
}

func TestCallBuiltIn_WrongArgCount(t *testing.T) {
	_, err := CallBuiltIn("calculate_severity", SomeStringValue("unlikely", nil))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected 2 parameters")
}

func TestCallBuiltIn_UnknownFunction(t *testing.T) {
	_, err := CallBuiltIn("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown built-in")
}
