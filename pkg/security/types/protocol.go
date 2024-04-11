/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type Protocol int

const (
	UnknownProtocol Protocol = iota
	HTTP
	HTTPS
	WS
	WSS
	ReverseProxyWebProtocol
	ReverseProxyWebProtocolEncrypted
	MQTT
	JDBC
	JdbcEncrypted
	ODBC
	OdbcEncrypted
	SqlAccessProtocol
	SqlAccessProtocolEncrypted
	NosqlAccessProtocol
	NosqlAccessProtocolEncrypted
	BINARY
	BinaryEncrypted
	TEXT
	TextEncrypted
	SSH
	SshTunnel
	SMTP
	SmtpEncrypted
	POP3
	Pop3Encrypted
	IMAP
	ImapEncrypted
	FTP
	FTPS
	SFTP
	SCP
	LDAP
	LDAPS
	JMS
	NFS
	SMB
	SmbEncrypted
	LocalFileAccess
	NRPE
	XMPP
	IIOP
	IiopEncrypted
	JRMP
	JrmpEncrypted
	InProcessLibraryCall
	ContainerSpawning
)

func ProtocolValues() []TypeEnum {
	return []TypeEnum{
		UnknownProtocol,
		HTTP,
		HTTPS,
		WS,
		WSS,
		ReverseProxyWebProtocol,
		ReverseProxyWebProtocolEncrypted,
		MQTT,
		JDBC,
		JdbcEncrypted,
		ODBC,
		OdbcEncrypted,
		SqlAccessProtocol,
		SqlAccessProtocolEncrypted,
		NosqlAccessProtocol,
		NosqlAccessProtocolEncrypted,
		BINARY,
		BinaryEncrypted,
		TEXT,
		TextEncrypted,
		SSH,
		SshTunnel,
		SMTP,
		SmtpEncrypted,
		POP3,
		Pop3Encrypted,
		IMAP,
		ImapEncrypted,
		FTP,
		FTPS,
		SFTP,
		SCP,
		LDAP,
		LDAPS,
		JMS,
		NFS,
		SMB,
		SmbEncrypted,
		LocalFileAccess,
		NRPE,
		XMPP,
		IIOP,
		IiopEncrypted,
		JRMP,
		JrmpEncrypted,
		InProcessLibraryCall,
		ContainerSpawning,
	}
}

var ProtocolTypeDescription = [...]TypeDescription{
	{"unknown-protocol", "Unknown protocol"},
	{"http", "HTTP protocol"},
	{"https", "HTTPS protocol (encrypted)"},
	{"ws", "WebSocket"},
	{"wss", "WebSocket but encrypted"},
	{"reverse-proxy-web-protocol", "Protocols used by reverse proxies"},
	{"reverse-proxy-web-protocol-encrypted", "Protocols used by reverse proxies but encrypted"},
	{"mqtt", "MQTT Message protocol. Encryption via TLS is optional"},
	{"jdbc", "Java Database Connectivity"},
	{"jdbc-encrypted", "Java Database Connectivity but encrypted"},
	{"odbc", "Open Database Connectivity"},
	{"odbc-encrypted", "Open Database Connectivity but encrypted"},
	{"sql-access-protocol", "SQL access protocol"},
	{"sql-access-protocol-encrypted", "SQL access protocol but encrypted"},
	{"nosql-access-protocol", "NOSQL access protocol"},
	{"nosql-access-protocol-encrypted", "NOSQL access protocol but encrypted"},
	{"binary", "Some other binary protocol"},
	{"binary-encrypted", "Some other binary protocol, encrypted"},
	{"text", "Some other text protocol"},
	{"text-encrypted", "Some other text protocol, encrypted"},
	{"ssh", "Secure Shell to execute commands"},
	{"ssh-tunnel", "Secure Shell as a tunnel"},
	{"smtp", "Mail transfer protocol (sending)"},
	{"smtp-encrypted", "Mail transfer protocol (sending), encrypted"},
	{"pop3", "POP 3 mail fetching"},
	{"pop3-encrypted", "POP 3 mail fetching, encrypted"},
	{"imap", "IMAP mail sync protocol"},
	{"imap-encrypted", "IMAP mail sync protocol, encrypted"},
	{"ftp", "File Transfer Protocol"},
	{"ftps", "FTP with TLS"},
	{"sftp", "FTP on SSH"},
	{"scp", "Secure Shell to copy files"},
	{"ldap", "Lightweight Directory Access Protocol - User directories"},
	{"ldaps", "Lightweight Directory Access Protocol - User directories on TLS"},
	{"jms", "Jakarta Messaging"},
	{"nfs", "Network File System"},
	{"smb", "Server Message Block"},
	{"smb-encrypted", "Server Message Block, but encrypted"},
	{"local-file-access", "Data files are on the local system"},
	{"nrpe", "Nagios Remote Plugin Executor"},
	{"xmpp", "Extensible Messaging and Presence Protocol"},
	{"iiop", "Internet Inter-ORB Protocol "},
	{"iiop-encrypted", "Internet Inter-ORB Protocol , encrypted"},
	{"jrmp", "Java Remote Method Protocol"},
	{"jrmp-encrypted", "Java Remote Method Protocol, encrypted"},
	{"in-process-library-call", "Call to local library"},
	{"container-spawning", "Spawn a container"},
}

func ParseProtocol(value string) (protocol Protocol, err error) {
	value = strings.TrimSpace(value)
	for _, candidate := range ProtocolValues() {
		if candidate.String() == value {
			return candidate.(Protocol), err
		}
	}
	return protocol, fmt.Errorf("unable to parse into type: %v", value)
}

func (what Protocol) String() string {
	// NOTE: maintain list also in schema.json for validation in IDEs
	return ProtocolTypeDescription[what].Name
}

func (what Protocol) Explain() string {
	return ProtocolTypeDescription[what].Description
}

func (what Protocol) IsProcessLocal() bool {
	return what == InProcessLibraryCall || what == LocalFileAccess || what == ContainerSpawning
}

func (what Protocol) IsEncrypted() bool {
	return what == HTTPS || what == WSS || what == JdbcEncrypted || what == OdbcEncrypted ||
		what == NosqlAccessProtocolEncrypted || what == SqlAccessProtocolEncrypted || what == BinaryEncrypted || what == TextEncrypted || what == SSH || what == SshTunnel ||
		what == FTPS || what == SFTP || what == SCP || what == LDAPS || what == ReverseProxyWebProtocolEncrypted ||
		what == IiopEncrypted || what == JrmpEncrypted || what == SmbEncrypted || what == SmtpEncrypted || what == Pop3Encrypted || what == ImapEncrypted
}

func (what Protocol) IsPotentialDatabaseAccessProtocol(includingLaxDatabaseProtocols bool) bool {
	strictlyDatabaseOnlyProtocol := what == JdbcEncrypted || what == OdbcEncrypted ||
		what == NosqlAccessProtocolEncrypted || what == SqlAccessProtocolEncrypted || what == JDBC || what == ODBC || what == NosqlAccessProtocol || what == SqlAccessProtocol
	if includingLaxDatabaseProtocols {
		// include HTTP for REST-based NoSQL-DBs as well as unknown binary
		return strictlyDatabaseOnlyProtocol || what == HTTPS || what == HTTP || what == BINARY || what == BinaryEncrypted
	}
	return strictlyDatabaseOnlyProtocol
}

func (what Protocol) IsPotentialWebAccessProtocol() bool {
	return what == HTTP || what == HTTPS || what == WS || what == WSS || what == ReverseProxyWebProtocol || what == ReverseProxyWebProtocolEncrypted
}

func (what Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(what.String())
}

func (what *Protocol) UnmarshalJSON(data []byte) error {
	var text string
	unmarshalError := json.Unmarshal(data, &text)
	if unmarshalError != nil {
		return unmarshalError
	}

	value, findError := what.find(text)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Protocol) MarshalYAML() (interface{}, error) {
	return what.String(), nil
}

func (what *Protocol) UnmarshalYAML(node *yaml.Node) error {
	value, findError := what.find(node.Value)
	if findError != nil {
		return findError
	}

	*what = value
	return nil
}

func (what Protocol) find(value string) (Protocol, error) {
	for index, description := range ProtocolTypeDescription {
		if strings.EqualFold(value, description.Name) {
			return Protocol(index), nil
		}
	}

	return Protocol(0), fmt.Errorf("unknown protocol value %q", value)
}
