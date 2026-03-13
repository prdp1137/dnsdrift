package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/prdp1137/dnsdrift/internal/finding"
	"github.com/prdp1137/dnsdrift/internal/signature"
)

type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
)

type Writer struct {
	format Format
	w      io.Writer
	count  int
}

func NewWriter(format Format, w io.Writer) *Writer {
	return &Writer{format: format, w: w}
}

func (ow *Writer) WriteHeader() {
	if ow.format == FormatJSON {
		fmt.Fprint(ow.w, "[")
	} else {
		header := color.New(color.Bold)
		header.Fprintf(ow.w, "%-50s %-25s %-12s %s\n",
			"DOMAIN", "SERVICE", "CONFIDENCE", "INFO")
		fmt.Fprintln(ow.w, strings.Repeat("-", 120))
	}
}

func (ow *Writer) WriteFinding(f *finding.Finding) error {
	switch ow.format {
	case FormatJSON:
		if ow.count > 0 {
			fmt.Fprint(ow.w, ",")
		}
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		fmt.Fprint(ow.w, string(data))

	case FormatTable:
		confidenceColor := color.New(color.FgWhite)
		switch f.Confidence {
		case signature.Confirmed:
			confidenceColor = color.New(color.FgRed, color.Bold)
		case signature.Potential:
			confidenceColor = color.New(color.FgYellow)
		case signature.Unlikely:
			confidenceColor = color.New(color.FgCyan)
		}

		domain := f.Domain
		if len(domain) > 48 {
			domain = domain[:45] + "..."
		}

		service := f.Service
		if len(service) > 23 {
			service = service[:20] + "..."
		}

		info := f.Info
		if len(info) > 80 {
			info = info[:77] + "..."
		}

		fmt.Fprintf(ow.w, "%-50s %-25s ", domain, service)
		confidenceColor.Fprintf(ow.w, "%-12s ", string(f.Confidence))
		fmt.Fprintln(ow.w, info)
	}

	ow.count++
	return nil
}

func (ow *Writer) WriteFooter() {
	if ow.format == FormatJSON {
		fmt.Fprintln(ow.w, "]")
	} else if ow.count == 0 {
		color.New(color.FgGreen).Fprintln(ow.w, "No findings.")
	}
}

func (ow *Writer) Count() int {
	return ow.count
}
