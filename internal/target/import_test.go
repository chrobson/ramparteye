package target

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/ctx42/testing/pkg/assert"
)

func TestImportCSV(t *testing.T) {
	in := "value,tags\n10.20.0.0/24,lab;Web\n# comment\n\napp.LAB,web\n10.20.0.5\n10.20.0.0/24,extra\n"

	got, err := ImportCSV(strings.NewReader(in))

	assert.NoError(t, err)
	assert.Len(t, 3, got)
	assert.Equal(t, model.TargetCIDR, got[0].Kind)
	assert.Equal(t, "10.20.0.0/24", got[0].Value)
	assert.Equal(t, []string{"lab", "web", "extra"}, got[0].Tags) // merged duplicate
	assert.Equal(t, "app.lab", got[1].Value)
	assert.Equal(t, model.TargetIP, got[2].Kind)
}

func TestImportCSVTooBig(t *testing.T) {
	in := bytes.Repeat([]byte("a"), MaxImportBytes+1)

	_, err := ImportCSV(bytes.NewReader(in))

	assert.ErrorIs(t, ErrTooBig, err)
}

func TestImportCSVAtLimitIsNotTooBig(t *testing.T) {
	in := "10.0.0.1\n" + strings.Repeat("#", MaxImportBytes-len("10.0.0.1\n"))

	got, err := ImportCSV(strings.NewReader(in))

	assert.NoError(t, err)
	assert.Len(t, 1, got)
}

func TestImportCSVInvalidRowReportsLine(t *testing.T) {
	_, err := ImportCSV(strings.NewReader("value,tags\n10.0.0.1\n10.0.0.300\n"))

	assert.ErrorIs(t, ErrInvalidTarget, err)
	assert.ErrorContain(t, "line 3", err)
}

func TestImportCSVTooManyEntries(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxImportEntries; i++ {
		b.WriteString("10.0.0.1\n")
	}

	_, err := ImportCSV(strings.NewReader(b.String()))

	assert.ErrorIs(t, ErrTooManyEntries, err)
}

func TestImportJSON(t *testing.T) {
	in := `[{"value":"10.20.0.0/24","tags":["Lab"]},{"value":"app.lab","tags":"a;b"},{"value":"10.0.0.1-10.0.0.3"}]`

	got, err := ImportJSON(strings.NewReader(in))

	assert.NoError(t, err)
	assert.Len(t, 3, got)
	assert.Equal(t, []string{"lab"}, got[0].Tags)
	assert.Equal(t, []string{"a", "b"}, got[1].Tags)
	assert.Equal(t, model.TargetRange, got[2].Kind)
}

func TestImportJSONErrors(t *testing.T) {
	_, err := ImportJSON(strings.NewReader(`{"value":"x"}`))
	assert.Error(t, err)

	_, err = ImportJSON(strings.NewReader(`[{"value":"10.0.0.300"}]`))
	assert.ErrorIs(t, ErrInvalidTarget, err)

	_, err = ImportJSON(bytes.NewReader(bytes.Repeat([]byte(" "), MaxImportBytes+1)))
	assert.ErrorIs(t, ErrTooBig, err)
}
