package cattp

import(
	"testing"
	"encoding/hex"
)

func TestNibble(t *testing.T) {
	in := "8912"
	inb,err := hex.DecodeString(in)
	if err != nil {
		t.Errorf("Hex Decode failed: %s",err)
		return
	}
	outb := Nibble(inb)
	out := hex.EncodeToString(outb)

	t.Logf("%s",in)
	t.Logf("%s",hex.Dump(inb))
	t.Logf("%s",hex.Dump(outb))
	t.Logf("%s",out)

	if out != "9821" {
		t.Errorf("Nibble failed: '%s'/'%s'",string(inb),string(outb))
	}
}
