package reset

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"

	"github.com/pkg/errors"
)

type RequestorFuncArg func(*requestOpts)

type RequestOpts struct {
	// Log          xm.Logger
	Request      *http.Request // XXX
	HasData      bool
	Data         interface{}
	HasRaw       bool
	Raw          []bytes
	PathParams   map[string]string
	QueryParams  url.Values
	Encoder      func(interface{}) ([]byte, error)
	Decoder      func([]byte, interface{}) error
	DecodeReader func(io.Reader, interface{}) error
	Method       string
	HasReader    bool
	Reader       io.Reader
	Client       *http.Client
	Cookies      []*http.Cookie
	Context      context.Context
	DecodeStatus map[int]interface{}
	Before       func(*RequestOpts, *http.Request) error
	After        func(Result) Result
	AlwaysRead   bool
	Description  string
	// XXX expect response code
}

func (o RequestOpts) Copy() *RequestOpts {
	// XXX
}

func Make() *RequestOpts {
	return &RequestOpts{
		PathParams:   make(map[string]string),
		QueryParams:  make(url.Values),
		DecodeStatus: make(map[int]interface{}),
	}
}

func (o *RequestOpts) Describe(description string) *RequestOpts {
	o.Description = description
	return o
}

func (o *RequestOpts) AlwaysReadResponse() *RequestOpts {
	o.AlwaysRead = true
	return o
}

func (o *RequestOpts) DoBefore(f func(*RequestOpts, *http.Request) error) *RequestOpts {
	o.Before = f
	return o
}

func (o *RequestOpts) DoAfter(f func(Result) Result) *RequestOpts {
	o.After = f
	return o
}

func (o *RequestOpts) DecodeWith(f func([]byte, interface{}) error) *RequestOpts {
	o.Decoder = f
	return o
}

func (o *RequestOpts) DecodeWithReader(f func(io.Reader, interface{}) error) *RequestOpts {
	o.DecoderReader = f
	return o
}

func (o *RequestOpts) EncodeWith(f func(interface{}) ([]byte, error)) *RequestOpts {
	o.Encoder = f
	return o
}

func (o *RequestOpts) Client(client *http.Client) *RequestOpts {
	o.Client = client
	return o
}

func (o *RequestOpts) Get(url string) error {
	o.Method = http.MethodGet
	return o.DoAndDecode()
}

func (o *RequestOpts) Post(url string) error {
	o.Method = http.MethodPost
	return o.DoAndDecode()
}

func (o *RequestOpts) Post(url string) error {
	o.Method = http.MethodPost
	return o.DoAndDecode()
}

func (o *RequestOpts) Head(url string) error {
	o.Method = http.MethodHead
	return o.DoAndDecode()
}

func (o *RequestOpts) Delete(url string) error {
	o.Method = http.MethodDelete
	return o.DoAndDecode()
}

func (o *RequestOpts) Method(m string) *RequestOpts {
	o.Method = m
	return o
}

func (o *RequestOpts) Data(data interface{}) *RequestOpts {
	o.HasData = true
	o.Data = data
	return o
}

func (o *RequestOpts) BodyIO(reader io.Reader) *RequestOpts {
	o.HasReader = true
	o.Reader = reader
	return o
}

func (o *RequestOpts) Context(ctx context.Context) *RequestOpts {
	o.Context = ctx
	return o
}

func (o *RequestOpts) Cookie(cookie *http.Cookie) *RequestOpts {
	o.Cookies = append(o.Cookies, cookie)
	return o
}

func (o *RequestOpts) PathParam(name string, value interface{}) *RequestOpts {
	o.PathParams[name] = fmt.Sprint(value)
	return o
}

func (o *RequestOpts) Raw(raw []byte) *RequestOpts {
	o.HasRaw = true
	o.Raw = raw
	return o
}

func (o *RequestOpts) Decode(statusCode int, target interface{}) *RequestOpts {
	o.DecodeStatus[statusCode] = target
	return o
}

func (o *RequestOpts) Do() (result Result) {
	result.Options = o
	hasBody := o.HasRaw || o.HasData || o.HasReader

	switch o.Method {
	case "":
		o.Method = "GET"
		fallthrough
	case http.MethodGet:
		if hasBody {
			result.Error = errors.New("Cannot send data with method GET")
			return
		}
	case http.MethodHead:
		if hasBody {
			result.Error = errors.New("Cannot send data with method HEAD")
			return
		}
	case http.MethodPost:
		if !hasBody {
			result.Error = errors.New("Must have data to send for method POST")
			return
		}
	case http.MethodPut:
		if !hasBody {
			result.Error = errors.New("Must have data to send for method PUT")
			return
		}
	case http.MethodPatch:
		if !hasBody {
			result.Error = errors.New("Must have data to send for method PATCH")
			return
		}
	case http.MethodDelete:
	case http.MethodConnect:
	case http.MethodOptions:
		if hasBody {
			result.Error = errors.New("Cannot send data with method OPTIONS")
			return
		}
	case http.MethodTrace:
		if hasBody {
			result.Error = errors.New("Cannot send data with method TRACE")
			return
		}
	default:
		result.Error = Errorf("Unknown method '%s'", o.Method)
		return
	}

	if o.HasData && o.HasRaw {
		result.Error = errors.New("Cannot specify both a raw body and a model to encode")
		return
	}
	if o.HasData && o.Encoder == nil {
		result.Error = errors.New("Must specify an encoder when supplying a object to encode")
		return
	}
	if o.HasData {
		var err error
		o.Raw, err = o.Encoder(o.Data)
		if err != nil {
			return nil, errors.Wrap(err, "encode request")
		}
	}
	var reader io.Reader
	if o.HasReader {
		reader = o.HasReader
	} else if hasBody {
		reader = bytes.NewReader(o.Raw)
	}

	url := o.URL
	if o.BaseURL != "" {
		url = o.BaseURL + "/" + url
	}
	var subMissing string
	paramsRe.ReplaceAllStringFunc(url, func(key string) string {
		if value, ok := o.PathParams[key]; ok {
			return url.PathEscape(value)
		}
		subMissing = key
		return ""
	})
	if subMissing != "" {
		result.Error = errors.Errorf("No parameter for URL path substitution {%s}", subMissing)
		return
	}
	if len(o.QueryParams) != 0 {
		url += "?" + o.QueryParams.Encode()
	}

	if o.Context != nil {
		o.Context = context.Background()
	}
	request, err := http.NewRequestWithContext(o.Context, o.Method, url, reader)
	if err != nil {
		result.Error = errors.Wrap(err, "create request")
		return
	}

	for _, cookie := range o.Cookies {
		request.AddCookie(cookie)
	}

	if o.Client == nil {
		o.Client = http.DefaultClient
	}

	if o.Before != nil {
		err := o.Before(o, request)
		if err != nil {
			result.Error = err
			return
		}
	}

	if o.Description == "" {
		o.Description = o.Method + " " + o.URL
	}

	result.Response, result.Error = o.Client.Do(request)
	if result.Error != nil {
		return
	}
	if o.AlwaysRead && result.Response.Body != nil {
		result = result.ReadBody()
	}
	if target, ok := o.DecodeStatus[response.StatusCode]; ok {
		result = result.Decode(response.StatusCode, target)
		if o.After != nil {
			result = result.HandleAfter()
		}
	}
	return
}

type Result struct {
	Response     *http.Response
	Error        error
	Decoded      bool
	Read         bool
	Body         []byte
	Options      *RequestOpts
	DecodeTarget interface{}
	afterDone    bool
}

func (r Result) HandleAfter() Result {
	if r.Options.After == nil || r.AfterDone {
		return r
	}
	r.afterDone = true
	return r.Options.After(r)
}

func (r Result) Decode(statusCode int, target interface{}) Result {
	r = r.WillDecode()
	if r.Error != nil {
		return r
	}
	if r.Response.StatusCode != statusCode {
		return r
	}
	if r.Decoded {
		return r
	}
	var err error
	if r.DecodeReader != nil {
		r.Decoded = true
		body := r.Response.Body
		if r.Read {
			body = bytes.NewReader(r.Body)
		}
		err = r.DecodeReader(body, target)
	} else {
		r = r.ReadBody()
		if r.Error != nil {
			return r
		}
		if r.Decoder == nil {
			r.Error = errors.New("Cannot decode response because no decoder has been registererd")
			return r
		}
		r.Decoded = true
		err = r.Decoder(r.Body, target)
	}
	if err != nil {
		r.Error = errors.Wrap(err, "decode body")
	} else {
		r.DecodeTarget = target
	}
	return r
}

func (r Result) WillDecode() Result {
	if r.Error != nil {
		return r
	}
	switch r.Options.Method {
	case http.MethodConnect, http.MethodTrace, http.MethodHead, http.MethodPut:
		r.Error = errors.Errorf("No body with method %s", r.Options.Method)
		return r
	}
}

func (r Result) ReadBody() Result {
	if r.Error != nil {
		return r
	}
	if r.Read {
		return r
	}
	r.Read = true
	var err error
	r.Body, err = io.ReadAll(r.Response.Body)
	if err != nil {
		r.Error = errors.Wrap(err, "read response body")
		return r
	}
	return r
}

func (r Result) Done() Result {
	r = r.HandleAfter()
	return r
}

func (r Result) Error() error {
	r = r.HandleAfter()
	return r.Error
}

func (r Result) Status() (int, error) {
	r = r.HandleAfter()
	return r.Response.StatusCode, r.Error
}

func (r Result) Raw() (*http.Response, error) {
	r = r.HandleAfter()
	return r.Response, r.Error
}

func (o *RequestOpts) JSON() *RequestOpts {
	return o.
		DecodeWith(json.Unmarshal).
		EncodeWith(json.Marshal)
}

func (o *ReuqestOpts) StrictJSON() *RequestOpts {
	return o.
		DecodeWithReader(func(r io.Reader, t interface{}) error {
			decoder := json.NewDecoder()
			decoder.DisallowUnknownFields()
			return decoder.Decode(t)
		}).
		EncodeWith(json.Marshal)
}

func (o *RequestOpts) XML() *RequestOpts {
	return o.
		DecodeWith(xml.Unmarshal).
		EncodeWith(xml.Marshal)
}
