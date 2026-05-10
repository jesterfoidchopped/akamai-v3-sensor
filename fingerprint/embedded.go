package fingerprint

import (
	"embed"
	"io/fs"
	"log"
	"path"
	"strings"
)

//go:embed embedded/*.json
var embeddedPresets embed.FS

func init() {
	entries, err := fs.ReadDir(embeddedPresets, "embedded")
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := embeddedPresets.ReadFile(path.Join("embedded", e.Name()))
		if err != nil {
			log.Printf("sensor: failed to read embedded preset %s: %v", e.Name(), err)
			continue
		}
		pf, err := LoadPresetFromJSON(data)
		if err != nil {
			log.Printf("sensor: failed to parse embedded preset %s: %v", e.Name(), err)
			continue
		}
		if pf.Preset == nil {
			log.Printf("sensor: embedded preset %s has no preset section, skipping", e.Name())
			continue
		}
		p, err := BuildPreset(pf.Preset)
		if err != nil {
			log.Printf("sensor: failed to build embedded preset %s: %v", e.Name(), err)
			continue
		}
		Register(p.Name, p)
	}
}
