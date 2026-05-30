// Package output renders domain values for the CLI as table, JSON or YAML.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"gopkg.in/yaml.v3"
)

// Format is a CLI output format.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// YAML writes v as YAML.
func YAML(w io.Writer, v any) error {
	return yaml.NewEncoder(w).Encode(v)
}

// ServersTable writes a server list as an aligned table.
func ServersTable(w io.Writer, servers []upcloud.Server) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UUID\tHOSTNAME\tPLAN\tZONE\tSTATE")
	for _, s := range servers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.UUID, s.Hostname, s.Plan, s.Zone, s.State)
	}
	return tw.Flush()
}

// ServerDetailsText writes a single server's key fields as aligned key/value lines.
func ServerDetailsText(w io.Writer, d *upcloud.ServerDetails) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "UUID\t%s\n", d.UUID)
	fmt.Fprintf(tw, "Hostname\t%s\n", d.Hostname)
	fmt.Fprintf(tw, "Title\t%s\n", d.Title)
	fmt.Fprintf(tw, "Plan\t%s\n", d.Plan)
	fmt.Fprintf(tw, "Zone\t%s\n", d.Zone)
	fmt.Fprintf(tw, "State\t%s\n", d.State)
	return tw.Flush()
}
