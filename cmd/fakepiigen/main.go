package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bxcodec/faker"

	"github.com/k0kubun/pp"

	rd "github.com/Pallinder/go-randomdata"
	"github.com/icrowley/fake"
)

var lines = 300

var stats = map[string]int{}

func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if len(os.Args) != 2 {
		panic(errors.New("must provide an output file for fake data"))
	}
	data := []string{}
	for x := 0; x < lines; x++ {
		data = append(data, roulette())
	}

	err := ioutil.WriteFile(os.Args[1], []byte(strings.Join(data, "\n")), 0644)
	if err != nil {
		panic(err)
	}

	pp.Println(stats)
}

func roulette() string {
	roll := random(0, 15)
	switch roll {
	case 0:
		stats["color"]++
		return fake.Color()
	case 1:
		stats["credit_card"]++
		p := faker.GetPayment()
		return p.CreditCardNumber()
	case 2:
		stats["8_digits"]++
		return fake.DigitsN(8)
	case 3:
		stats["url"]++
		u := faker.GetNetworker()
		return u.Url()
	case 4:
		stats["email"]++
		return fake.EmailAddress()
	case 5:
		stats["full_name"]++
		return fake.FullName()
	case 6:
		stats["hex_color"]++
		return fake.HexColor()
	case 7:
		stats["ipv4"]++
		return fake.IPv4()
	case 8:
		stats["ipv6"]++
		return fake.IPv6()
	case 9:
		stats["language"]++
		return fake.Language()
	case 10:
		stats["model_num"]++
		return fake.Model()
	case 11:
		stats["phone"]++
		p := faker.GetPhoner()
		return p.E164PhoneNumber()
	case 12:
		stats["straddr"]++
		return strings.Replace(rd.Address(), "\n", " ", -1)
	case 13:
		stats["uuid"]++
		return uuid.New().String()
	default:
		stats["paragraph"]++
		return fake.Paragraph()
	}
}

func straddr() string {
	return fmt.Sprintf("%s %s, %s, %s", fake.StreetAddress(), fake.City(), fake.StateAbbrev(), fake.Zip())
}
