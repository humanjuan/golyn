package test

import (
	"testing"

	"github.com/go-ini/ini"

	"github.com/humanjuan/golyn/config/loaders"
)

func TestCheckString(t *testing.T) {
	sectionName := "settings"
	fieldName := "name"

	// nil key, required
	if _, ok, err := loaders.CheckString(nil, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for missing required key")
	}
	// nil key, optional
	if v, ok, err := loaders.CheckString(nil, false, sectionName, fieldName); !ok || err != nil || v != "" {
		t.Fatalf("expected ok with empty value for optional missing key, got ok=%v err=%v v=%q", ok, err, v)
	}

	cfg := ini.Empty()
	sec, _ := cfg.NewSection(sectionName)

	// empty value, required -> error
	key, _ := sec.NewKey(fieldName, "")
	if _, ok, err := loaders.CheckString(key, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for empty required string")
	}
	// empty value, optional -> ok
	if v, ok, err := loaders.CheckString(key, false, sectionName, fieldName); !ok || err != nil || v != "" {
		t.Fatalf("expected ok for empty optional string, got ok=%v err=%v v=%q", ok, err, v)
	}
	// non-empty value
	key.SetValue("hello")
	if v, ok, err := loaders.CheckString(key, true, sectionName, fieldName); !ok || err != nil || v != "hello" {
		t.Fatalf("expected v=hello ok=true err=nil, got v=%q ok=%v err=%v", v, ok, err)
	}
}

func TestCheckInt(t *testing.T) {
	sectionName := "settings"
	fieldName := "number"

	// nil key, required
	if _, ok, err := loaders.CheckInt(nil, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for missing required int key")
	}
	// nil key, optional
	if v, ok, err := loaders.CheckInt(nil, false, sectionName, fieldName); !ok || err != nil || v != 0 {
		t.Fatalf("expected ok with zero for optional missing key, got ok=%v err=%v v=%d", ok, err, v)
	}

	cfg := ini.Empty()
	sec, _ := cfg.NewSection(sectionName)
	key, _ := sec.NewKey(fieldName, "")

	// empty, required -> error
	if _, ok, err := loaders.CheckInt(key, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for empty required int")
	}
	// empty, optional -> ok zero
	if v, ok, err := loaders.CheckInt(key, false, sectionName, fieldName); !ok || err != nil || v != 0 {
		t.Fatalf("expected ok for empty optional int, got ok=%v err=%v v=%d", ok, err, v)
	}
	// invalid numeric
	key.SetValue("abc")
	if _, ok, err := loaders.CheckInt(key, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for invalid int value")
	}
	// valid numeric
	key.SetValue("42")
	if v, ok, err := loaders.CheckInt(key, true, sectionName, fieldName); !ok || err != nil || v != 42 {
		t.Fatalf("expected 42 ok=true err=nil, got v=%d ok=%v err=%v", v, ok, err)
	}
}

func TestCheckBool(t *testing.T) {
	sectionName := "settings"
	fieldName := "flag"

	// nil key, required
	if _, ok, err := loaders.CheckBool(nil, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for missing required bool key")
	}
	// nil key, optional
	if v, ok, err := loaders.CheckBool(nil, false, sectionName, fieldName); !ok || err != nil || v != false {
		t.Fatalf("expected ok with false for optional missing key, got ok=%v err=%v v=%v", ok, err, v)
	}

	cfg := ini.Empty()
	sec, _ := cfg.NewSection(sectionName)
	key, _ := sec.NewKey(fieldName, "")

	// empty, required -> error
	if _, ok, err := loaders.CheckBool(key, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for empty required bool")
	}
	// empty, optional -> ok false
	if v, ok, err := loaders.CheckBool(key, false, sectionName, fieldName); !ok || err != nil || v != false {
		t.Fatalf("expected ok for empty optional bool false, got ok=%v err=%v v=%v", ok, err, v)
	}
	// invalid bool
	key.SetValue("maybe")
	if _, ok, err := loaders.CheckBool(key, true, sectionName, fieldName); ok || err == nil {
		t.Fatalf("expected error for invalid bool value")
	}
	// valid true
	key.SetValue("true")
	if v, ok, err := loaders.CheckBool(key, true, sectionName, fieldName); !ok || err != nil || v != true {
		t.Fatalf("expected true ok=true err=nil, got v=%v ok=%v err=%v", v, ok, err)
	}
	// valid false
	key.SetValue("false")
	if v, ok, err := loaders.CheckBool(key, true, sectionName, fieldName); !ok || err != nil || v != false {
		t.Fatalf("expected false ok=true err=nil, got v=%v ok=%v err=%v", v, ok, err)
	}
}
