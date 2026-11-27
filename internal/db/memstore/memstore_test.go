package memstore_test

import (
	"testing"

	"github.com/boson-chat/pushrelay/internal/db/memstore"
	repo "github.com/boson-chat/pushrelay/internal/db/repositories"
	"github.com/boson-chat/pushrelay/internal/db/storetest"
)

func TestContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) repo.Store { return memstore.New() })
}
