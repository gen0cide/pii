package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fatih/color"

	"github.com/gen0cide/pii"
	"github.com/urfave/cli"
)

var (
	findEnabled   = false
	detectEnabled = true
	searchCommand = cli.Command{
		Name:      "search",
		Usage:     "determine what kind, if any, PII exists within a file(s)",
		UsageText: "pii search [OPTIONS] FILE [FILE] [FILE...]",
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:        "find-matches",
				Usage:       "Seek through data to return match literals",
				Destination: &findEnabled,
			},
		},
		Action: searchcommand,
	}
)

func searchcommand(c *cli.Context) error {
	if c.Args().Get(0) == "" {
		return errors.New("must provide an argument to this command")
	}

	t := pii.NewDefaultTester()

	for _, x := range c.Args() {
		cliLogger.Infof("Adding file %s", x)
		err := t.AddNewFile(x)
		if err != nil {
			return err
		}
	}

	cliLogger.Infof("Setting up matcher...")

	t.SetDetection(detectEnabled)
	t.SetFinder(findEnabled)
	t.Setup()

	cliLogger.Infof("Performing detections...")

	errs := t.PerformDetections(w)

	if len(errs) != 0 {
		for _, f := range errs {
			cliLogger.Errorf("%v", f)
		}
	}

	if findEnabled {
		t.PerformMatches(w)
	}

	t.CalcAverages()

	if jsonOutput {
		jsonData, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(jsonData))
	} else {
		return printsearchresults(t)
	}

	return nil
}

func printsubstat(label string, val bool) {
	res := color.HiGreenString("PRESENT")
	if !val {
		res = color.RedString("NOT FOUND")
	}
	cliLogger.Infof("%19s: %-20s", label, res)
}

func printsearchresults(t *pii.Tester) error {
	for _, x := range t.Files {
		cliLogger.Logger.Infof("##############################\n# FILE: %s", color.HiYellowString(x.Filename))
		cliLogger.Logger.Infof("##############################")
		for r, v := range x.Hits {
			printsubstat(r, v)
		}
		cliLogger.Logger.Info("")

	}
	return nil
}
