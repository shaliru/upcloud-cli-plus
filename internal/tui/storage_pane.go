package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/cloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

// storagePane is a read-only list + detail pane for storage. Detail is fetched
// on enter (StorageDetails carries attached servers + backup info).
type storagePane struct {
	list         table.Model
	detail       viewport.Model
	devices      []upcloud.Storage
	backups      []upcloud.Storage
	customImages []upcloud.Storage
	sub          int // 0 = devices, 1 = backups, 2 = custom images
	loaded       bool
}

func storageColumns() []table.Column {
	return []table.Column{
		{Title: "UUID", Width: 36},
		{Title: "TITLE", Width: 24},
		{Title: "SIZE (GB)", Width: 9},
		{Title: "ZONE", Width: 9},
		{Title: "TIER", Width: 8},
		{Title: "TYPE", Width: 8},
		{Title: "STATE", Width: 10},
	}
}

func storageRows(items []upcloud.Storage) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, s := range items {
		rows = append(rows, table.Row{s.UUID, s.Title, fmt.Sprintf("%d", s.Size), s.Zone, s.Tier, s.Type, dotState(s.State)})
	}
	return rows
}

func newStoragePane() storagePane {
	t := table.New(table.WithColumns(storageColumns()), table.WithFocused(true), table.WithHeight(10))
	return storagePane{list: t, detail: viewport.New()}
}

func (p *storagePane) setItems(items []upcloud.Storage) {
	p.devices = cloud.FilterStorageByCategory(items, "devices")
	p.backups = cloud.FilterStorageByCategory(items, "backups")
	p.customImages = cloud.FilterStorageByCategory(items, "images")
	p.loaded = true
	p.refreshRows()
}

// active returns the storages for the current sub-category.
func (p *storagePane) active() []upcloud.Storage {
	switch p.sub {
	case 1:
		return p.backups
	case 2:
		return p.customImages
	default:
		return p.devices
	}
}

func (p *storagePane) refreshRows() {
	p.list.SetRows(storageRows(p.active()))
	if len(p.active()) > 0 {
		p.list.SetCursor(0)
	}
}

func (p *storagePane) nextSub() { p.sub = (p.sub + 1) % 3; p.refreshRows() }
func (p *storagePane) prevSub() { p.sub = (p.sub + 2) % 3; p.refreshRows() }

func (p *storagePane) subBar() string {
	return renderTabs(p.sub, []string{"Devices", "Backups", "Custom images"})
}

func (p *storagePane) selectedUUID() (string, bool) {
	items := p.active()
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(items) {
		return "", false
	}
	return items[cur].UUID, true
}

func (p *storagePane) listView() string {
	if len(p.active()) == 0 {
		return styles.Muted.Render("  (none)")
	}
	return p.list.View()
}

func (p *storagePane) detailView() string { return p.detail.View() }

// renderStorageDetail renders storage details (read-only), width-bounded.
func renderStorageDetail(d *upcloud.StorageDetails, width int) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(styles.Title.Render(truncate(d.Title, width)) + "\n")
	b.WriteString(styles.Muted.Render(truncate(d.UUID, width)) + "\n\n")
	b.WriteString(styles.Title.Render("Overview") + "\n")
	b.WriteString(kv("Size (GB)", fmt.Sprintf("%d", d.Size), width))
	b.WriteString(kv("Zone", d.Zone, width))
	b.WriteString(kv("Tier", d.Tier, width))
	b.WriteString(kv("Type", d.Type, width))
	b.WriteString(kv("State", d.State, width))
	b.WriteString("\n")
	b.WriteString(styles.Title.Render("Attached to") + "\n")
	if len(d.ServerUUIDs) == 0 {
		b.WriteString(styles.Muted.Render("  (not attached)") + "\n")
	}
	for _, uuid := range d.ServerUUIDs {
		b.WriteString(truncate("  "+uuid, width) + "\n")
	}
	return b.String()
}
