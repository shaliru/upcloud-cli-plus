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

// StoragesTable writes a storage list as an aligned table.
func StoragesTable(w io.Writer, storages []upcloud.Storage) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UUID\tTITLE\tSIZE (GB)\tZONE\tTIER\tSTATE")
	for _, s := range storages {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", s.UUID, s.Title, s.Size, s.Zone, s.Tier, s.State)
	}
	return tw.Flush()
}

// StorageDetailsText writes a single storage's key fields as aligned key/value lines.
func StorageDetailsText(w io.Writer, d *upcloud.StorageDetails) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "UUID\t%s\n", d.UUID)
	fmt.Fprintf(tw, "Title\t%s\n", d.Title)
	fmt.Fprintf(tw, "Size (GB)\t%d\n", d.Size)
	fmt.Fprintf(tw, "Zone\t%s\n", d.Zone)
	fmt.Fprintf(tw, "Tier\t%s\n", d.Tier)
	fmt.Fprintf(tw, "Type\t%s\n", d.Type)
	fmt.Fprintf(tw, "State\t%s\n", d.State)
	return tw.Flush()
}

// NetworksTable writes a network list as an aligned table.
func NetworksTable(w io.Writer, networks []upcloud.Network) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UUID\tNAME\tTYPE\tZONE")
	for _, n := range networks {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n.UUID, n.Name, n.Type, n.Zone)
	}
	return tw.Flush()
}

// NetworkDetailsText writes a single network's key fields and its IP networks.
func NetworkDetailsText(w io.Writer, n *upcloud.Network) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "UUID\t%s\n", n.UUID)
	fmt.Fprintf(tw, "Name\t%s\n", n.Name)
	fmt.Fprintf(tw, "Type\t%s\n", n.Type)
	fmt.Fprintf(tw, "Zone\t%s\n", n.Zone)
	for _, ipn := range n.IPNetworks {
		fmt.Fprintf(tw, "IP network\t%s\t%s\tgw %s\n", ipn.Address, ipn.Family, ipn.Gateway)
	}
	return tw.Flush()
}
