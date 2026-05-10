package client

import (
	http "github.com/sardanioss/http"
)

type HookType string

const (
	HookPreRequest   HookType = "pre_request"
	HookPostResponse HookType = "post_response"
)

type PreRequestHook func(req *http.Request) error

type PostResponseHook func(resp *Response) error

type Hooks struct {
	preRequest   []PreRequestHook
	postResponse []PostResponseHook
}

func NewHooks() *Hooks {
	return &Hooks{
		preRequest:   make([]PreRequestHook, 0),
		postResponse: make([]PostResponseHook, 0),
	}
}

func (h *Hooks) OnPreRequest(hook PreRequestHook) *Hooks {
	h.preRequest = append(h.preRequest, hook)
	return h
}

func (h *Hooks) OnPostResponse(hook PostResponseHook) *Hooks {
	h.postResponse = append(h.postResponse, hook)
	return h
}

func (h *Hooks) RunPreRequest(req *http.Request) error {
	if h == nil {
		return nil
	}
	for _, hook := range h.preRequest {
		if err := hook(req); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) RunPostResponse(resp *Response) error {
	if h == nil {
		return nil
	}
	for _, hook := range h.postResponse {
		if err := hook(resp); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hooks) Clear() {
	h.preRequest = make([]PreRequestHook, 0)
	h.postResponse = make([]PostResponseHook, 0)
}

func (h *Hooks) ClearPreRequest() {
	h.preRequest = make([]PreRequestHook, 0)
}

func (h *Hooks) ClearPostResponse() {
	h.postResponse = make([]PostResponseHook, 0)
}
