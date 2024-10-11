package models

type SplunkEvent struct {
	Event      map[string]interface{} `json:"event"`
	Host       string                 `json:"host"`
	Sourcetype string                 `json:"sourcetype"`
	Source     string                 `json:"source"`
	Index      string                 `json:"index"`
}
