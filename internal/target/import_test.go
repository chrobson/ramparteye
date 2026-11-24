package target

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/chrobson/ramparteye/internal/model"
	"github.com/ctx42/testing/pkg/assert"
)

func TestImportCSV(t *testing.T) {
	in := "value,tags\n10.20.0.0/24,lab;Web\n# comment\n\napp.LAB,web\n10.20.0.5\n10.20.0.0/24,extra\n"

	got, err := importCSV(strings.NewReader(in))

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

	_, err := importCSV(bytes.NewReader(in))

	assert.ErrorIs(t, ErrTooBig, err)
}

func TestImportCSVAtLimitIsNotTooBig(t *testing.T) {
	in := "10.0.0.1\n" + strings.Repeat("#", MaxImportBytes-len("10.0.0.1\n"))

	got, err := importCSV(strings.NewReader(in))

	assert.NoError(t, err)
	assert.Len(t, 1, got)
}

func TestImportCSVInvalidRowReportsLine(t *testing.T) {
	_, err := importCSV(strings.NewReader("value,tags\n10.0.0.1\n10.0.0.300\n"))

	assert.ErrorIs(t, ErrInvalidTarget, err)
	assert.ErrorContain(t, "line 3", err)
}

func TestImportCSVTooManyEntries(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxImportEntries; i++ {
		b.WriteString("10.0.0.1\n")
	}

	_, err := importCSV(strings.NewReader(b.String()))

	assert.ErrorIs(t, ErrTooManyEntries, err)
}

func TestImportJSON(t *testing.T) {
	in := `[{"value":"10.20.0.0/24","tags":["Lab"]},{"value":"app.lab","tags":"a;b"},{"value":"10.0.0.1-10.0.0.3"}]`

	got, err := importJSON(strings.NewReader(in))

	assert.NoError(t, err)
	assert.Len(t, 3, got)
	assert.Equal(t, []string{"lab"}, got[0].Tags)
	assert.Equal(t, []string{"a", "b"}, got[1].Tags)
	assert.Equal(t, model.TargetRange, got[2].Kind)
}

func TestImportJSONErrors(t *testing.T) {
	_, err := importJSON(strings.NewReader(`{"value":"x"}`))
	assert.Error(t, err)

	_, err = importJSON(strings.NewReader(`[{"value":"10.0.0.300"}]`))
	assert.ErrorIs(t, ErrInvalidTarget, err)

	_, err = importJSON(bytes.NewReader(bytes.Repeat([]byte(" "), MaxImportBytes+1)))
	assert.ErrorIs(t, ErrTooBig, err)
}

func TestImportLines(t *testing.T) {
	csv := "value,tags\n\n# comment\n10.0.0.1,a\n10.0.0.2\n10.0.0.1,b\nexample.com\n"
	ts, lines, err := ImportCSVLines(strings.NewReader(csv))
	assert.NoError(t, err)
	assert.Len(t, 3, ts)
	assert.Equal(t, []int{4, 5, 7}, lines)
	assert.Equal(t, []string{"a", "b"}, ts[0].Tags)

	js := "[\n {\"value\": \"10.0.0.1\"},\n {\"value\": \"10.0.0.1\"},\n {\"value\": \"10.0.0.3\"}\n]"
	ts, lines, err = ImportJSONLines(strings.NewReader(js))
	assert.NoError(t, err)
	assert.Len(t, 2, ts)
	assert.Equal(t, []int{2, 4}, lines)
}

func importCSV(r io.Reader) ([]model.Target, error) {
	ts, _, err := ImportCSVLines(r)
	return ts, err
}

func importJSON(r io.Reader) ([]model.Target, error) {
	ts, _, err := ImportJSONLines(r)
	return ts, err
}
