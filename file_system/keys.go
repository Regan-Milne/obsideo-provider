package file_system

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// SplitMerkle parses a key of the form "{hex_merkle}/{owner}/{start}" (the part after "tree/").
func SplitMerkle(key []byte) (merkle []byte, owner string, start int64, err error) {
	its := strings.Split(string(key), "/")
	if len(its) < 3 {
		return nil, "", 0, fmt.Errorf("invalid tree key: %s", string(key))
	}
	merkle, err = hex.DecodeString(its[0])
	if err != nil {
		return nil, "", 0, err
	}
	start, err = strconv.ParseInt(its[2], 10, 64)
	if err != nil {
		return nil, "", 0, err
	}
	owner = its[1]
	return merkle, owner, start, nil
}

func treeKey(merkle []byte, owner string, start int64) []byte {
	return []byte(fmt.Sprintf("tree/%x/%s/%d", merkle, owner, start))
}
