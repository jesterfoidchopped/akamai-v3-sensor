package fingerprint

import (
	"fmt"
	"sync"
)

var customPresets sync.Map

func Register(name string, preset *Preset) {
	if preset == nil {
		return
	}
	customPresets.Store(name, preset)
}

func RegisterStrict(name string, preset *Preset) error {
	if preset == nil {
		return fmt.Errorf("preset is nil")
	}
	if name == "" {
		return fmt.Errorf("preset name is empty")
	}
	if _, exists := customPresets.Load(name); exists {
		return fmt.Errorf("preset name %q already registered (call Unregister first to replace)", name)
	}
	if _, builtin := presets[name]; builtin {
		return fmt.Errorf("preset name %q collides with a built-in — pick a different name", name)
	}
	customPresets.Store(name, preset)
	return nil
}

func Unregister(name string) {
	customPresets.Delete(name)
}

func LookupCustom(name string) *Preset {
	if v, ok := customPresets.Load(name); ok {
		p, _ := v.(*Preset)
		if p != nil {
			return clonePreset(p)
		}
	}
	return nil
}
