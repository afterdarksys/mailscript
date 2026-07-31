package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"time"
)

type clamAVScanner struct {
	endpoint string
	client   *http.Client
}
type clamAVResponse struct {
	VirusFound bool   `json:"virus_found"`
	Signature  string `json:"signature"`
	Status     string `json:"status"`
}

func (s *clamAVScanner) scan(ctx context.Context, message []byte) (clamAVResponse, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	p, err := w.CreateFormFile("file", "message.eml")
	if err != nil {
		return clamAVResponse{}, err
	}
	if _, err = p.Write(message); err != nil {
		return clamAVResponse{}, err
	}
	if err = w.Close(); err != nil {
		return clamAVResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/rest/v1/scan", &body)
	if err != nil {
		return clamAVResponse{}, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := s.client.Do(req)
	if err != nil {
		return clamAVResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return clamAVResponse{}, fmt.Errorf("clamav api returned %s", resp.Status)
	}
	var result clamAVResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return clamAVResponse{}, err
	}
	return result, nil
}

func newClamAVScanner(endpoint string, timeout time.Duration) *clamAVScanner {
	return &clamAVScanner{endpoint: endpoint, client: &http.Client{Timeout: timeout}}
}
