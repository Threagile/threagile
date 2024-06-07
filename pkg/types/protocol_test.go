/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ParseProtocolTest struct {
	input         string
	expected      Protocol
	expectedError error
}

func TestParseProtocol(t *testing.T) {
	testCases := map[string]ParseProtocolTest{
		"unknown-protocol": {
			input:    "unknown-protocol",
			expected: UnknownProtocol,
		},
		"http": {
			input:    "http",
			expected: HTTP,
		},
		"https": {
			input:    "https",
			expected: HTTPS,
		},
		"ws": {
			input:    "ws",
			expected: WS,
		},
		"wss": {
			input:    "wss",
			expected: WSS,
		},
		"reverse-proxy-web-protocol": {
			input:    "reverse-proxy-web-protocol",
			expected: ReverseProxyWebProtocol,
		},
		"reverse-proxy-web-protocol-encrypted": {
			input:    "reverse-proxy-web-protocol-encrypted",
			expected: ReverseProxyWebProtocolEncrypted,
		},
		"mqtt": {
			input:    "mqtt",
			expected: MQTT,
		},
		"jdbc": {
			input:    "jdbc",
			expected: JDBC,
		},
		"jdbc-encrypted": {
			input:    "jdbc-encrypted",
			expected: JdbcEncrypted,
		},
		"odbc": {
			input:    "odbc",
			expected: ODBC,
		},
		"odbc-encrypted": {
			input:    "odbc-encrypted",
			expected: OdbcEncrypted,
		},
		"sql-access-protocol": {
			input:    "sql-access-protocol",
			expected: SqlAccessProtocol,
		},
		"sql-access-protocol-encrypted": {
			input:    "sql-access-protocol-encrypted",
			expected: SqlAccessProtocolEncrypted,
		},
		"nosql-access-protocol": {
			input:    "nosql-access-protocol",
			expected: NosqlAccessProtocol,
		},
		"nosql-access-protocol-encrypted": {
			input:    "nosql-access-protocol-encrypted",
			expected: NosqlAccessProtocolEncrypted,
		},
		"binary": {
			input:    "binary",
			expected: BINARY,
		},
		"binary-encrypted": {
			input:    "binary-encrypted",
			expected: BinaryEncrypted,
		},
		"text": {
			input:    "text",
			expected: TEXT,
		},
		"text-encrypted": {
			input:    "text-encrypted",
			expected: TextEncrypted,
		},
		"ssh": {
			input:    "ssh",
			expected: SSH,
		},
		"ssh-tunnel": {
			input:    "ssh-tunnel",
			expected: SshTunnel,
		},
		"smtp": {
			input:    "smtp",
			expected: SMTP,
		},
		"smtp-encrypted": {
			input:    "smtp-encrypted",
			expected: SmtpEncrypted,
		},
		"pop3": {
			input:    "pop3",
			expected: POP3,
		},
		"pop3-encrypted": {
			input:    "pop3-encrypted",
			expected: Pop3Encrypted,
		},
		"imap": {
			input:    "imap",
			expected: IMAP,
		},
		"imap-encrypted": {
			input:    "imap-encrypted",
			expected: ImapEncrypted,
		},
		"ftp": {
			input:    "ftp",
			expected: FTP,
		},
		"ftps": {
			input:    "ftps",
			expected: FTPS,
		},
		"sftp": {
			input:    "sftp",
			expected: SFTP,
		},
		"scp": {
			input:    "scp",
			expected: SCP,
		},
		"ldap": {
			input:    "ldap",
			expected: LDAP,
		},
		"ldaps": {
			input:    "ldaps",
			expected: LDAPS,
		},
		"jms": {
			input:    "jms",
			expected: JMS,
		},
		"nfs": {
			input:    "nfs",
			expected: NFS,
		},
		"smb": {
			input:    "smb",
			expected: SMB,
		},
		"smb-encrypted": {
			input:    "smb-encrypted",
			expected: SmbEncrypted,
		},
		"local-file-access": {
			input:    "local-file-access",
			expected: LocalFileAccess,
		},
		"nrpe": {
			input:    "nrpe",
			expected: NRPE,
		},
		"xmpp": {
			input:    "xmpp",
			expected: XMPP,
		},
		"iiop": {
			input:    "iiop",
			expected: IIOP,
		},
		"iiop-encrypted": {
			input:    "iiop-encrypted",
			expected: IiopEncrypted,
		},
		"jrmp": {
			input:    "jrmp",
			expected: JRMP,
		},
		"jrmp-encrypted": {
			input:    "jrmp-encrypted",
			expected: JrmpEncrypted,
		},
		"in-process-library-call": {
			input:    "in-process-library-call",
			expected: InProcessLibraryCall,
		},
		"container-spawning": {
			input:    "container-spawning",
			expected: ContainerSpawning,
		},
		"unknown": {
			input:         "unknown",
			expectedError: fmt.Errorf("unable to parse into type: unknown"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			actual, err := ParseProtocol(testCase.input)

			assert.Equal(t, testCase.expected, actual)
			assert.Equal(t, testCase.expectedError, err)
		})
	}
}
