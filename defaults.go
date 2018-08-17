package pii

var (
	// DefaultRuleSet provides a rule set of default PII rules
	DefaultRuleSet = RuleSet{
		"phone_number":   defaultPhoneRule,
		"ssn":            defaultSSNRule,
		"email_address":  defaultEmailRule,
		"ip_address":     defaultIPRule,
		"credit_card":    defaultCreditCardRule,
		"street_address": defaultAddressRule,
		"banking_info":   defaultBankInfoRule,
		"uuid":           defaultUUIDRule,
		"vin":            defaultVINRule,
		// "link":           defaultLinkRule,
	}

	defaultPhoneRule = Rule{
		Name:        "phone_number",
		Description: "phone number",
		Severity:    3,
		Filter:      Phone(),
		Exporter:    ExportPhones,
	}

	defaultLinkRule = Rule{
		Name:        "link",
		Description: "link or URL",
		Severity:    1,
		Filter:      Link(),
		Exporter:    ExportLinks,
	}

	defaultSSNRule = Rule{
		Name:        "ssn",
		Description: "social security number",
		Severity:    5,
		Filter:      SSN(),
		Exporter:    ExportSSNs,
	}

	defaultEmailRule = Rule{
		Name:        "email_address",
		Description: "valid email address",
		Severity:    3,
		Filter:      Email(),
		Exporter:    ExportEmails,
	}

	defaultIPRule = Rule{
		Name:        "ip_address",
		Description: "valid IPv4 or IPv6 address",
		Severity:    2,
		Filter:      IP(),
		Exporter:    ExportIPs,
	}

	defaultCreditCardRule = Rule{
		Name:        "credit_card",
		Description: "valid credit card number",
		Severity:    5,
		Filter:      CreditCard(),
		Exporter:    ExportCreditCards,
	}

	defaultAddressRule = Rule{
		Name:        "street_address",
		Description: "street address or PO box",
		Severity:    3,
		Filter:      Address(),
		Exporter:    ExportAddresses,
	}

	defaultBankInfoRule = Rule{
		Name:        "banking_info",
		Description: "IBAN or ACH routing number",
		Severity:    5,
		Filter:      BankInfo(),
		Exporter:    ExportBankInfos,
	}

	defaultUUIDRule = Rule{
		Name:        "uuid",
		Description: "valid UUID (v3,v4,v5) or GUID",
		Severity:    3,
		Filter:      UUID(),
		Exporter:    ExportUUIDs,
	}

	defaultVINRule = Rule{
		Name:        "vin",
		Description: "vehicle identification number (VIN)",
		Severity:    2,
		Filter:      VIN(),
		Exporter:    ExportVINs,
	}
)
