package types

type Overview struct {
	Description string
	Images      []map[string]string // yes, array of map here, as array keeps the order of the image keys
}
