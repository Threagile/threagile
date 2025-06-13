package types

type configReader interface {
	GetAppFolder() string
	GetTechnologyFilename() string
}

