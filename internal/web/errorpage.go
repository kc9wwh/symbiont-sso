package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strconv"
)

// ErrorPage is a user-facing error. Messages must never include internal
// details (tokens, XML, stack traces); those belong in logs.
type ErrorPage struct {
	Status  int
	Title   string
	Message string
	// RequestID helps operators correlate the page with logs.
	RequestID string
}

var errorTmpl = template.Must(template.New("err").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>{{.Title}}</title><style>{{.Style}}</style></head>
<body><h1>{{.Title}}</h1><p>{{.Message}}</p>
{{if .RequestID}}<p><small>Reference: {{.RequestID}}</small></p>{{end}}
</body></html>
`))

// errorCSP allows only the static stylesheet; no scripts, no forms.
var errorCSP = "default-src 'none'; style-src " + styleHash + "; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// WriteError renders an HTML error page.
func WriteError(w http.ResponseWriter, p ErrorPage) {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	var buf bytes.Buffer
	if err := errorTmpl.Execute(&buf, struct {
		ErrorPage
		Style template.CSS
	}{p, template.CSS(pageStyle)}); err != nil {
		http.Error(w, http.StatusText(p.Status), p.Status)
		return
	}
	h := w.Header()
	SetCSP(w, errorCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(p.Status)
	_, _ = w.Write(buf.Bytes())
}
