package tests

import (
	"testing"
	"github.com/ryadavDeqode/dq-vault/api/helpers"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestNewUUID(t *testing.T){
	uuid := helpers.NewUUID()
	len := len(uuid)
	if len == 0{
		t.Error("uuid is of size 0")

	}
	if len != 20{
		t.Error("uuid invalid!")
	}
}


func TestErrMissingField(t *testing.T){

	
	
	errMissingField := helpers.ErrMissingField("")

	if errMissingField != logical.ErrorResponse("missing required") {
		t.Error(errMissingField)
	}

	
	// if errMissingField 
	
}

// func TestValidateFields(t *testing.T){
// 	t.Error(status)
// }
