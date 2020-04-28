package fame

import "github.com/fentec-project/gofe/abe"

// MSP stub for abe MSP
type MSP struct {
	RowToAttrib []string
	*abe.MSP
}

// NewMSP returns a new MSP
func NewMSP() *MSP {
	m := new(MSP)
	m.MSP = new(abe.MSP)

	return m
}

// BooleanToMSP BooleanToMSP
func BooleanToMSP(boolExp string, convertToOnes bool) (*MSP, error) {
	m, err := abe.BooleanToMSP(boolExp, convertToOnes, "string")
	if err != nil {
		return nil, err
	}

	msp := &MSP{
		RowToAttrib: m.RowToAttribS,
		MSP:         m,
	}

	return msp, nil
}
