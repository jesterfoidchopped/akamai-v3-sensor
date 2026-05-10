package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/client"
)

type ECHInfo struct {
	ECHSuccess bool   `json:"ech_success"`
	OuterSNI   string `json:"outer_sni"`
}

type TLSInfo struct {
	ECH ECHInfo `json:"ech"`
}

type ServerResponse struct {
	UserAgent string  `json:"user_agent,omitempty"`
	JA4       string  `json:"ja4,omitempty"`
	TLS       TLSInfo `json:"tls"`
}

type RequestResult struct {
	RequestNum     int             `json:"request_num"`
	Success        bool            `json:"success"`
	Error          string          `json:"error,omitempty"`
	Protocol       string          `json:"protocol,omitempty"`
	ECHSuccess     bool            `json:"ech_success"`
	OuterSNI       string          `json:"outer_sni,omitempty"`
	JA4            string          `json:"ja4,omitempty"`
	JA4Extensions  string          `json:"ja4_extensions,omitempty"`
	NewConnection  bool            `json:"new_connection"`
	RTTMs          float64         `json:"rtt_ms"`
	ServerResponse *ServerResponse `json:"server_response,omitempty"`
}

type TestResults struct {
	TestName   string          `json:"test_name"`
	Server     string          `json:"server"`
	Timestamp  string          `json:"timestamp"`
	Transport  string          `json:"transport"`
	Results    []RequestResult `json:"results"`
	AllPassed  bool            `json:"all_passed"`
	ECHWorking bool            `json:"ech_working"`
	ZeroRTT    bool            `json:"zero_rtt_working"`
	Summary    string          `json:"summary"`
}

func main() {
	ctx := context.Background()

	echConfig, err := base64.StdEncoding.DecodeString("AFb+DQBSCQAgACCv9VgyhBjSIX5QZS44OkBQC8H5c4+b2u20pF/4sbkEUgAMAAEAAQABAAIAAQADABtxdWljLW91dGVyLmJyb3dzZXJsZWFrcy5jb20AAA==")
	if err != nil {
		fmt.Printf("Failed to decode ECH config: %v\n", err)
		return
	}

	c := client.NewClient("chrome-latest",
		client.WithTimeout(30*time.Second),
		client.WithECHConfig(echConfig),
	)
	defer c.Close()

	testResults := TestResults{
		TestName:  "ECH + 0-RTT over QUIC/HTTP3 Test",
		Server:    "quic.browserleaks.com",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Transport: "QUIC/HTTP3",
		Results:   make([]RequestResult, 0, 3),
	}

	result1 := makeRequest(ctx, c, 1, true)
	testResults.Results = append(testResults.Results, result1)

	time.Sleep(1 * time.Second)

	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	result2 := makeRequest(ctx, c, 2, true)
	testResults.Results = append(testResults.Results, result2)

	c.CloseQUICConnections()
	time.Sleep(500 * time.Millisecond)

	result3 := makeRequest(ctx, c, 3, true)
	testResults.Results = append(testResults.Results, result3)

	allPassed := true
	echWorking := true
	for _, r := range testResults.Results {
		if !r.Success {
			allPassed = false
		}
		if !r.ECHSuccess {
			echWorking = false
		}
	}

	zeroRTTWorking := false
	if len(testResults.Results) >= 2 {
		ja4_1 := testResults.Results[0].JA4Extensions
		ja4_2 := testResults.Results[1].JA4Extensions
		if ja4_1 == "11" && ja4_2 == "13" {
			zeroRTTWorking = true
		}
	}

	testResults.AllPassed = allPassed && echWorking && zeroRTTWorking
	testResults.ECHWorking = echWorking
	testResults.ZeroRTT = zeroRTTWorking

	if echWorking && zeroRTTWorking {
		testResults.Summary = "ECH + 0-RTT working: ECH maintained on all requests, 0-RTT session resumption successful"
	} else if echWorking {
		testResults.Summary = "ECH working but 0-RTT not detected"
	} else if allPassed {
		testResults.Summary = "HTTP/3 working but ECH NOT accepted by server"
	} else {
		testResults.Summary = "Some requests failed"
	}

	jsonOutput, err := json.MarshalIndent(testResults, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonOutput))
}

func makeRequest(ctx context.Context, c *client.Client, reqNum int, isNewConnection bool) RequestResult {
	result := RequestResult{
		RequestNum:    reqNum,
		NewConnection: isNewConnection,
	}

	start := time.Now()

	resp, err := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})

	result.RTTMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		result.Error = fmt.Sprintf("request error: %v", err)
		return result
	}

	result.Protocol = string(resp.Protocol)

	text, err := resp.Text()
	if err != nil {
		result.Error = fmt.Sprintf("read body error: %v", err)
		return result
	}

	var serverResp ServerResponse
	if err := json.Unmarshal([]byte(text), &serverResp); err == nil {
		result.ServerResponse = &serverResp
		result.ECHSuccess = serverResp.TLS.ECH.ECHSuccess
		result.OuterSNI = serverResp.TLS.ECH.OuterSNI
		result.JA4 = serverResp.JA4

		if len(serverResp.JA4) >= 9 {
			result.JA4Extensions = serverResp.JA4[6:8]
		}
	}

	result.Success = true
	return result
}
