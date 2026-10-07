package web

import (
	"bytes"
	"html/template"
	"net/http"
	"strconv"
)

// autoSubmitScript is the only script on POST-binding pages. It is static
// (no interpolated data) so its CSP hash is a compile-time constant. Field
// values live in the form's hidden inputs, never in script.
const autoSubmitScript = `document.getElementById("f").submit();`

// pageStyle hides the fallback button while the script runs and keeps the
// noscript experience readable. Static, so it is allowed by hash.
const pageStyle = `body{font-family:system-ui,sans-serif;margin:3em auto;max-width:32em;padding:0 1em;color:#222}` +
	`button{font-size:1em;padding:.5em 1.25em}`

var (
	scriptHash = ScriptHash(autoSubmitScript)
	styleHash  = ScriptHash(pageStyle)
)

// AutoSubmitScriptHash is the CSP hash of the POST-binding page script.
func AutoSubmitScriptHash() string { return scriptHash }

// PostFormPage describes an auto-submitting HTTP-POST binding page.
type PostFormPage struct {
	// Action is the absolute URL the form posts to.
	Action string
	// FormAction is the CSP form-action source: the Action origin, or
	// "'self'" for same-origin replays.
	FormAction string
	// Fields are posted as hidden inputs, in order.
	Fields []Field
	// Title is shown in the <noscript> fallback.
	Title string
}

// Field is a hidden form input.
type Field struct{ Name, Value string }

var postFormTmpl = template.Must(template.New("post").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>{{.Title}}</title><style>{{.Style}}</style></head>
<body><form id="f" method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<noscript><p>{{.Title}}</p><p>JavaScript is disabled. Press the button to continue.</p><button type="submit">Continue</button></noscript>
</form><script>{{.Script}}</script></body></html>
`))

// WritePostForm renders p with a per-response CSP that allows exactly the
// auto-submit script and only p.FormAction as a form target.
func WritePostForm(w http.ResponseWriter, p PostFormPage) error {
	if p.Title == "" {
		p.Title = "Signing you in…"
	}
	var buf bytes.Buffer
	err := postFormTmpl.Execute(&buf, struct {
		PostFormPage
		Script template.JS
		Style  template.CSS
	}{p, template.JS(autoSubmitScript), template.CSS(pageStyle)})
	if err != nil {
		return err
	}
	h := w.Header()
	SetCSP(w, PostFormCSP(scriptHash, p.FormAction))
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(buf.Bytes())
	return err
}
