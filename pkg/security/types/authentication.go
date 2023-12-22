/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package types

type Authentication int

const (
	NoneAuthentication Authentication = iota
	Credentials
	SessionId
	Token
	ClientCertificate
	TwoFactor
	Externalized
)

func AuthenticationValues() []TypeEnum {
	return []TypeEnum{
		NoneAuthentication,
		Credentials,
		SessionId,
		Token,
		ClientCertificate,
		TwoFactor,
		Externalized,
	}
}

var AuthenticationTypeDescription = [...]TypeDescription{
	{"none", "No authentication"},
	{"credentials", "Username and password, pin or passphrase"},
	{"session-id", "A server generated session id with limited life span"},
	{"token", "A server generated token. Containing session id, other data and is cryptographically signed"},
	{"client-certificate", "A certificate file stored on the client identifying this specific client"},
	{"two-factor", "Credentials plus another factor like a physical object (card) or biometrics"},
	{"externalized", "Some external company handles authentication"},
}

func (what Authentication) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	//return [...]string{"none", "credentials", "session-id", "token", "client-certificate", "two-factor", "externalized"}[what]
	return AuthenticationTypeDescription[what].Name
}

func (what Authentication) Explain() string {
	return AuthenticationTypeDescription[what].Description
}
