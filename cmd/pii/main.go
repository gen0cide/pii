package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/fatih/color"
	"github.com/gen0cide/gscript/logger/standard"
	"github.com/gen0cide/pii"
	"github.com/gen0cide/waiter"
	"github.com/urfave/cli"
)

var (
	cliLogger     = standard.NewStandardLogger(nil, "pii", "cli", false, true)
	displayBefore = true
	jsonOutput    = false
	w             = waiter.New("", ioutil.Discard)
)

func init() {
	cli.HelpFlag = cli.BoolFlag{Name: "help, h"}
	cli.VersionFlag = cli.BoolFlag{Name: "version"}

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Fprintf(c.App.Writer, "%s\n", pii.Version)
	}
}

func main() {
	app := cli.NewApp()

	app.Writer = color.Output
	app.ErrWriter = color.Output

	app.Name = "pii"
	app.Usage = "identify PII in files"
	app.Description = "Match or export common PII formats from files"

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:        "json, j",
			Usage:       "output results as JSON",
			Destination: &jsonOutput,
		},
	}

	app.Version = pii.Version
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Alex Levinson",
			Email: "alexl@uber.com",
		},
	}
	app.Copyright = "(c) 2018 Alex Levinson"
	app.Commands = []cli.Command{
		searchCommand,
	}

	app.Before = func(c *cli.Context) error {
		if jsonOutput {
			cliLogger.Logger.Out = ioutil.Discard
		} else {
			w = waiter.New("pii", color.Output)
			cliLogger.Logger.Out = w
		}
		return nil
	}

	// ignore error so we don't exit non-zero and break gfmrun README example tests
	err := app.Run(os.Args)
	if err != nil {
		cliLogger.Fatalf("Error Encountered: %v", err)
	}
}

func commandNotImplemented(c *cli.Context) error {
	return fmt.Errorf("%s command not implemented", c.Command.FullName())
}
