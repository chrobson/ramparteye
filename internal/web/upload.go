package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Multipart upload limits.
const (
	uploadOverhead  = 64 << 10 // multipart framing and small fields on top of the file
	maxUploadFields = 16
	maxFieldBytes   = 4 << 10
)

var (
	errNotMultipart = errors.New("not a multipart form")
	errNoFile       = errors.New("no file in the form")
	errEmptyFile    = errors.New("the file is empty")
	errFileTooLarge = errors.New("file too large")
	errBadUpload    = errors.New("the form could not be read")
)

// upload is a multipart form read into memory: one file and small text
// fields.
type upload struct {
	Name   string
	Data   []byte
	Fields map[string]string
}

// readUpload reads the multipart body of r without spilling it to disk:
// the file part named field (at most limit bytes) and up to
// maxUploadFields text fields. The caller bounds r.Body with
// http.MaxBytesReader.
func readUpload(r *http.Request, field string, limit int64) (upload, error) {
	up := upload{Fields: map[string]string{}}
	mr, err := r.MultipartReader()
	if err != nil {
		return up, errNotMultipart
	}
	found := false
	for n := 0; ; n++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return up, errFileTooLarge
		}
		if err != nil || n > maxUploadFields {
			return up, errBadUpload
		}
		name := part.FormName()
		switch {
		case name == field && part.FileName() != "" && !found:
			b, err := io.ReadAll(io.LimitReader(part, limit+1))
			if errors.As(err, &mbe) || int64(len(b)) > limit {
				_ = part.Close()
				return up, errFileTooLarge
			}
			if err != nil {
				_ = part.Close()
				return up, errBadUpload
			}
			up.Name, up.Data, found = part.FileName(), b, true
		case part.FileName() == "":
			b, err := io.ReadAll(io.LimitReader(part, maxFieldBytes+1))
			if err != nil || len(b) > maxFieldBytes {
				_ = part.Close()
				return up, errBadUpload
			}
			up.Fields[name] = string(b)
		}
		_ = part.Close()
	}
	switch {
	case !found:
		return up, errNoFile
	case len(up.Data) == 0:
		return up, errEmptyFile
	}
	return up, nil
}

// uploadError maps a readUpload error to a status and a message; what
// names the expected file ("a CSV or JSON file").
func uploadError(err error, limit int64, what string) (int, string) {
	switch {
	case errors.Is(err, errFileTooLarge):
		return http.StatusRequestEntityTooLarge, fmt.Sprintf("The file is larger than %d MiB.", limit>>20)
	case errors.Is(err, errEmptyFile):
		return http.StatusBadRequest, "The file is empty."
	case errors.Is(err, errNoFile), errors.Is(err, errNotMultipart):
		return http.StatusBadRequest, "Choose " + what + " to upload."
	}
	return http.StatusBadRequest, "The upload could not be read; try again."
}
