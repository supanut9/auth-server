package uuid

import gouuid "github.com/google/uuid"

type Generator struct{}

func NewGenerator() Generator {
	return Generator{}
}

func (Generator) NewID() (string, error) {
	id, err := gouuid.NewV7()
	if err != nil {
		return "", err
	}

	return id.String(), nil
}
