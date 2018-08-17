package pii

import (
	"strings"
)

// ExportCreditCards attempts to extract all credit card numbers from a string
func ExportCreditCards(s string) (matches []string) {
	baseMatches := creditCardBaseRegexp.FindAllString(s, -1)
	for _, match := range baseMatches {
		noDash := strings.Replace(match, `-`, ``, -1)
		noSpace := strings.Replace(noDash, ` `, ``, -1)
		if matchtestcreditcard(noSpace) {
			continue
		}
		if luhn(noSpace) || luhn(noDash) || luhn(match) {
			matches = append(matches, match)
		}
	}

	return matches
}

// ExportPhones attempts to extract all phone matches from a string
func ExportPhones(s string) (matches []string) {
	baseMatches := phoneRegexp.FindAllString(s, -1)
	baseMatches = append(baseMatches, phonesWithExtsRegexp.FindAllString(s, -1)...)
	for _, m := range baseMatches {
		if matchemail(m) || matchfilename(m) || matchrepeatingnumber(m) {
			continue
		}
		matches = append(matches, m)
	}

	return matches
}

// ExportLinks attempts to grab all links and URLs from a string
func ExportLinks(s string) (matches []string) {
	baseMatches := urlRegexp.FindAllString(s, -1)
	baseMatches = append(baseMatches, urlRegexp.FindAllString(s, -1)...)
	for _, m := range baseMatches {
		if matchemail(m) {
			continue
		}
		matches = append(matches, m)
	}
	return matches
}

// ExportSSNs attempts to extract all SSN and India PAN number matches from a string
func ExportSSNs(s string) (matches []string) {
	baseMatches := ssnRegexp.FindAllString(s, -1)
	baseMatches = append(baseMatches, indiaPanRegexp.FindAllString(s, -1)...)
	for _, m := range baseMatches {
		if matchphone(m) || matchfilename(m) || matchrepeatingnumber(m) {
			continue
		}
		matches = append(matches, m)
	}
	return matches
}

// ExportEmails attempts to extract all email address matches from a string
func ExportEmails(s string) (matches []string) {
	return emailRegexp.FindAllString(s, -1)
}

// ExportIPs attempts to extract all IP Address matches from a string
func ExportIPs(s string) (matches []string) {
	baseMatches := ipv4Regexp.FindAllString(s, -1)
	baseMatches = append(baseMatches, ipv6Regexp.FindAllString(s, -1)...)
	return baseMatches
}

// ExportAddresses is not really working - disregard for the meantime.
func ExportAddresses(s string) (matches []string) {
	matches = streetAddressRegexp.FindAllString(s, -1)
	return matches
}

// ExportBankInfos attempts to extract all bank info matches from a string
func ExportBankInfos(s string) (matches []string) {
	baseMatches := ibanRegexp.FindAllString(s, -1)
	for _, bc := range usbanks {
		baseMatches = append(baseMatches, bc.FindAllString(s, -1)...)
	}
	for _, m := range baseMatches {
		if matchrepeatingnumber(m) {
			continue
		}
		matches = append(matches, m)
	}
	return matches
}

// ExportUUIDs attempts to extract all UUID matches from a string
func ExportUUIDs(s string) (matches []string) {
	baseMatches := map[string]bool{}
	for _, m := range uuidRegexp.FindAllString(s, -1) {
		if baseMatches[m] == true {
			continue
		}
		baseMatches[m] = true
	}
	for _, m := range uuid3Regexp.FindAllString(s, -1) {
		if baseMatches[m] == true {
			continue
		}
		baseMatches[m] = true
	}
	for _, m := range uuid4Regexp.FindAllString(s, -1) {
		if baseMatches[m] == true {
			continue
		}
		baseMatches[m] = true
	}
	for _, m := range uuid5Regexp.FindAllString(s, -1) {
		if baseMatches[m] == true {
			continue
		}
		baseMatches[m] = true
	}
	for m := range baseMatches {
		if matchfilename(m) {
			continue
		}
		matches = append(matches, m)
	}

	// for _, m := range guidRegexp.FindAllString(s, -1) {
	// 	if baseMatches[m] == true {
	// 		continue
	// 	}
	// 	baseMatches[m] = true
	// }

	return matches
}

// ExportVINs attempts to extract all VIN matches from a string
func ExportVINs(s string) (matches []string) {
	baseMatches := vinRegexp.FindAllString(s, -1)
	for _, m := range baseMatches {
		if matchfilename(m) || matchrepeatingnumber(m) || matchemail(m) {
			continue
		}
		if !matchvin(m) {
			continue
		}
		matches = append(matches, m)
	}
	return matches
}
