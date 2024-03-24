package path

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

type DerivationPath []uint32

func Parse(path string) (DerivationPath, error) {
	var result DerivationPath

	segments := strings.Split(path, "/")
	switch {
	case len(segments) == 0:
		return nil, errors.New("empty derivation path")
	case strings.TrimSpace(segments[0]) == "":
		return nil, errors.New("path must start with 'm/' prefix")
	case strings.TrimSpace(segments[0]) == "m" && len(segments) == 1: // if only leading /m is present
		return nil, errors.New("path contains invalid number of segments")
	}

	segments = segments[1:] // remove leading 'm'
	for _, segment := range segments {
		// ignore any whitespace
		segment = strings.TrimSpace(segment)
		var value uint32

		// handle hardened paths
		if strings.HasSuffix(segment, "'") {
			value = hdkeychain.HardenedKeyStart
			segment = strings.TrimSpace(strings.TrimSuffix(segment, "'"))
		}

		// handle non-hardened component
		val, ok := new(big.Int).SetString(segment, 0)
		if !ok {
			return nil, fmt.Errorf("invalid segment: %s", segment)
		}

		max := math.MaxUint32 - value
		if val.Sign() < 0 || val.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("segment %v is out of allowed range [0, %d]", val, max)
			}
			return nil, fmt.Errorf("segment %v is out of allowed hardened range [0, %d]", val, max)
		}

		value += uint32(val.Uint64())
		result = append(result, value)
	}

	return result, nil
}
