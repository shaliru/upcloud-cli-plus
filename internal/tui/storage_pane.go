package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	lipgloss "charm.land/lipgloss/v2"
	"github.com/UpCloudLtd/upcloud-go-api/v8/upcloud"
	"github.com/shaliru/upcloud-cli-plus/internal/tui/styles"
)

const storageListWidth = 56 // TITLE+SIZE+ZONE+TIER+STATE + cell padding

// lipglossJoin places two panes side by side (top-aligned). Defined here and
// reused by the network pane and the App.
func lipglossJoin(left, right string) string {
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// storagePane is a read-only list + detail pane for storage. Detail is fetched
// on enter (StorageDetails carries attached servers + backup info).
type storagePane struct {
	list   table.Model
	detail viewport.Model
	items  []upcloud.Storage
	loaded bool
	width  int
	height int
}

func storageColumns() []table.Column {
	return []table.Column{
		{Title: "TITLE", Width: 20},
		{Title: "SIZE (GB)", Width: 9},
		{Title: "ZONE", Width: 9},
		{Title: "TIER", Width: 8},
		{Title: "STATE", Width: 8},
	}
}

func storageRows(items []upcloud.Storage) []table.Row {
	rows := make([]table.Row, 0, len(items))
	for _, s := range items {
		rows = append(rows, table.Row{s.Title, fmt.Sprintf("%d", s.Size), s.Zone, s.Tier, s.State})
	}
	return rows
}

func newStoragePane() storagePane {
	t := table.New(table.WithColumns(storageColumns()), table.WithFocused(true), table.WithHeight(10))
	return storagePane{list: t, detail: viewport.New()}
}

func (p *storagePane) setItems(items []upcloud.Storage) {
	p.items = items
	p.loaded = true
	p.list.SetRows(storageRows(items))
}

func (p *storagePane) selectedUUID() (string, bool) {
	cur := p.list.Cursor()
	if cur < 0 || cur >= len(p.items) {
		return "", false
	}
	return p.items[cur].UUID, true
}

func (p *storagePane) setDetail(d *upcloud.StorageDetails) {
	p.detail.SetContent(renderStorageDetail(d, p.detailWidth()))
	p.detail.GotoTop()
}

func (p *storagePane) setSize(w, h int) {
	p.width, p.height = w, h
	lw := storageListWidth
	if lw > w {
		lw = w
	}
	p.list.SetWidth(lw)
	p.list.SetHeight(h)
	p.detail.SetWidth(p.detailWidth())
	p.detail.SetHeight(h)
}

func (p *storagePane) detailWidth() int {
	w := p.width - storageListWidth - 1
	if w < 1 {
		return 1
	}
	return w
}

func (p *storagePane) view() string {
	return lipglossJoin(p.list.View(), p.detail.View())
}

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
