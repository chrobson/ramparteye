package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/chrobson/ramparteye/internal/auth"
	"github.com/chrobson/ramparteye/internal/nuclei"
	"github.com/chrobson/ramparteye/internal/store"
)

// Nuclei upload limits.
const (
	maxNucleiFiles = 50
	maxNucleiBody  = maxNucleiFiles*(nuclei.MaxTemplateBytes+1) + uploadOverhead
)

// nucleiFile is one uploaded template; TooLarge files are not read.
type nucleiFile struct {
	Name     string
	Data     []byte
	TooLarge bool
}

func (s *Server) nucleiPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "nuclei", NucleiData{})
}

// nucleiImport converts every uploaded template. Accepted ones are stored
// disabled for review; rejected ones are listed with the reason. An id
// that is already taken is rejected, never overwritten.
func (s *Server) nucleiImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxNucleiBody)
	files, err := readNucleiFiles(r)
	if err != nil {
		status := http.StatusBadRequest
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			status = http.StatusRequestEntityTooLarge
		}
		s.renderStatus(w, r, status, "nuclei", NucleiData{Error: err.Error()})
		return
	}
	d := NucleiData{Report: true}
	ids := s.sigStore()
	for _, f := range files {
		item := NucleiItem{File: f.Name}
		if f.TooLarge {
			item.Reason = fmt.Sprintf("larger than %d KiB", nuclei.MaxTemplateBytes>>10)
			d.Rejected = append(d.Rejected, item)
			continue
		}
		sg, err := nuclei.Convert(f.Data)
		var re *nuclei.RejectError
		switch {
		case errors.As(err, &re):
			item.Reason = re.Reason
		case err != nil:
			item.Reason = err.Error()
		default:
			item.ID, item.Name = sg.ID, sg.Name
			if _, gerr := ids.Get(r.Context(), sg.ID); gerr == nil {
				err = store.ErrSignatureExists
			} else if !errors.Is(gerr, store.ErrSignatureNotFound) {
				err = gerr
			} else {
				err = ids.Create(r.Context(), sg)
			}
			switch {
			case errors.Is(err, store.ErrSignatureExists):
				item.Reason = "a signature with id " + sg.ID + " already exists"
			case err != nil:
				s.log.Error("store nuclei signature", "id", sg.ID, "err", err)
				item.Reason = "could not be stored"
			}
		}
		if item.Reason != "" {
			d.Rejected = append(d.Rejected, item)
		} else {
			d.Imported = append(d.Imported, item)
		}
	}
	imported := make([]string, len(d.Imported))
	for i, it := range d.Imported {
		imported[i] = it.ID
	}
	u, _ := auth.CurrentUser(r.Context())
	s.audit(r, &u.ID, "signature.import", "signatures:nuclei",
		map[string]any{"imported": imported, "rejected": len(d.Rejected)})
	s.render(w, r, "nuclei", d)
}

// readNucleiFiles reads the "files" parts of the multipart body (at most
// maxNucleiFiles). A file over nuclei.MaxTemplateBytes is marked TooLarge
// and its content dropped; the caller bounds r.Body.
func readNucleiFiles(r *http.Request) ([]nucleiFile, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("Choose one or more nuclei template files (.yaml) to upload.")
	}
	var files []nucleiFile
	for n := 0; ; n++ {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, fmt.Errorf("The upload is too large: at most %d files of %d KiB each.",
				maxNucleiFiles, nuclei.MaxTemplateBytes>>10)
		}
		if err != nil || n > maxNucleiFiles+maxUploadFields {
			return nil, errors.New("The upload could not be read; try again.")
		}
		if part.FormName() != "files" || part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if len(files) == maxNucleiFiles {
			_ = part.Close()
			return nil, fmt.Errorf("Too many files: at most %d per upload.", maxNucleiFiles)
		}
		b, err := io.ReadAll(io.LimitReader(part, nuclei.MaxTemplateBytes+1))
		_ = part.Close()
		if errors.As(err, &mbe) {
			return nil, fmt.Errorf("The upload is too large: at most %d files of %d KiB each.",
				maxNucleiFiles, nuclei.MaxTemplateBytes>>10)
		}
		if err != nil {
			return nil, errors.New("The upload could not be read; try again.")
		}
		f := nucleiFile{Name: part.FileName(), Data: b}
		if len(b) > nuclei.MaxTemplateBytes {
			f.Data, f.TooLarge = nil, true
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, errors.New("Choose one or more nuclei template files (.yaml) to upload.")
	}
	return files, nil
}
