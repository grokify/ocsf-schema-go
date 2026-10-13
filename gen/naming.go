package gen

import (
	"strings"
	"unicode"
)

// initialisms maps snake_case words to their Go-idiomatic spelling. Words not
// listed are simply title-cased.
var initialisms = map[string]string{
	"acl":    "ACL",
	"ai":     "AI",
	"api":    "API",
	"cidr":   "CIDR",
	"cis":    "CIS",
	"cnc":    "CNC",
	"cpu":    "CPU",
	"csc":    "CSC",
	"cve":    "CVE",
	"cvss":   "CVSS",
	"cwe":    "CWE",
	"d3f":    "D3F",
	"d3fend": "D3FEND",
	"db":     "DB",
	"dce":    "DCE",
	"dhcp":   "DHCP",
	"dkim":   "DKIM",
	"dmarc":  "DMARC",
	"dns":    "DNS",
	"epss":   "EPSS",
	"fqdn":   "FQDN",
	"ftp":    "FTP",
	"gid":    "GID",
	"gpu":    "GPU",
	"guid":   "GUID",
	"hassh":  "HASSH",
	"http":   "HTTP",
	"https":  "HTTPS",
	"hw":     "HW",
	"iam":    "IAM",
	"id":     "ID",
	"idp":    "IDP",
	"imei":   "IMEI",
	"ip":     "IP",
	"ja3":    "JA3",
	"ja4":    "JA4",
	"json":   "JSON",
	"kb":     "KB",
	"ldap":   "LDAP",
	"mac":    "MAC",
	"mfa":    "MFA",
	"nfs":    "NFS",
	"ntp":    "NTP",
	"oauth":  "OAuth",
	"ocsf":   "OCSF",
	"os":     "OS",
	"osint":  "OSINT",
	"pid":    "PID",
	"rpc":    "RPC",
	"sbom":   "SBOM",
	"scim":   "SCIM",
	"sha":    "SHA",
	"smb":    "SMB",
	"smtp":   "SMTP",
	"spf":    "SPF",
	"sql":    "SQL",
	"ssh":    "SSH",
	"ssl":    "SSL",
	"sso":    "SSO",
	"tcp":    "TCP",
	"tid":    "TID",
	"tls":    "TLS",
	"tsig":   "TSIG",
	"ttl":    "TTL",
	"udp":    "UDP",
	"uid":    "UID",
	"url":    "URL",
	"uuid":   "UUID",
	"vlan":   "VLAN",
	"vpc":    "VPC",
	"vpn":    "VPN",
	"whois":  "WHOIS",
	"xml":    "XML",
}

// GoName converts an OCSF snake_case identifier to an exported Go name,
// applying the initialisms table word by word. Leading underscores (hidden
// definitions such as _entity) are dropped.
func GoName(snake string) string {
	var b strings.Builder
	for _, word := range strings.Split(strings.TrimLeft(snake, "_"), "_") {
		if word == "" {
			continue
		}
		if up, ok := initialisms[word]; ok {
			b.WriteString(up)
			continue
		}
		r := []rune(word)
		r[0] = unicode.ToUpper(r[0])
		b.WriteString(string(r))
	}
	return b.String()
}

// EnumIdent converts an enum member caption to a Go identifier fragment,
// e.g. "LDAP Account" -> "LDAPAccount", "TCP/IP" -> "TCPIP",
// "In-Progress" -> "InProgress". The result may start with a digit; callers
// always prefix it with a field name.
func EnumIdent(caption string) string {
	var b strings.Builder
	upperNext := true
	for _, r := range caption {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if upperNext {
				r = unicode.ToUpper(r)
				upperNext = false
			}
			b.WriteRune(r)
		default:
			upperNext = true
		}
	}
	return b.String()
}
