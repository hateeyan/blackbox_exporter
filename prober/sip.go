package prober

import (
	"bufio"
	"bytes"
	"context"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/google/uuid"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"math/rand"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"text/template"
	"time"
)

func ProbeSIP(ctx context.Context, target string, config config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	var (
		durationGaugeVec = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_sip_duration_seconds",
			Help: "Duration of sip options request.",
		})
		statusCodeGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_sip_response_code",
			Help: "SIP response code",
		}, []string{"reason"})
	)
	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(statusCodeGauge)

	conn, err := net.Dial("udp", target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target URL", "err", err)
		return false
	}
	defer conn.Close()

	message, err := prepareSIPMessage(target, conn.LocalAddr().String())
	if err != nil {
		return false
	}

	start := time.Now()

	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return false
	}
	if _, err := conn.Write(message); err != nil {
		return false
	}

	tr := textproto.NewReader(bufio.NewReader(conn))
	//parse firstLine
	//SIP/2.0 200 OK
	firstLine, err := tr.ReadLine()
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target URL", "err", err)
		return false
	}
	if !strings.HasPrefix(firstLine, "SIP/2.0 ") {
		return false
	}
	firstLine = firstLine[8:]
	if len(firstLine) < 5 {
		return false
	}
	strArray := strings.SplitN(firstLine, " ", 2)
	if len(strArray) < 2 || len(strArray[0]) != 3 {
		return false
	}
	code, err := strconv.Atoi(strArray[0])
	if err != nil || code < 100 || code > 999 {
		return false
	}
	reason := strArray[1]

	durationGaugeVec.Add(time.Since(start).Seconds())
	statusCodeGauge.WithLabelValues(reason).Set(float64(code))
	return true
}

func prepareSIPMessage(ruri string, viaaddr string) ([]byte, error) {
	const templateDefaultText = `{{.method}} sip:{{.ruri}} SIP/2.0
Via: SIP/2.0/UDP {{.viaaddr}};branch=z9hG4bKSG.{{.viabranch}}
From: <sip:{{.viaaddr}}>;tag={{.fromtag}}
To: <sip:{{.ruri}}>
Call-ID: {{.callid}}
CSeq: {{.cseqnum}} {{.method}}
{{if .useragent}}User-Agent: {{.useragent}}{{end}}
Content-Length: 0

`

	var buf bytes.Buffer
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	callId := uuid.New().String()
	fields := map[string]interface{}{
		"method":    "OPTIONS",
		"ruri":      ruri,
		"viaaddr":   viaaddr,
		"viabranch": callId,
		"fromtag":   callId,
		"cseqnum":   strconv.Itoa(r.Intn(499) + 1),
		"callid":    callId,
		"useragent": userAgentDefaultHeader,
	}

	tpl, err := template.New("sip").Parse(templateDefaultText)
	if err != nil {
		return nil, err
	}

	if err := tpl.Execute(&buf, fields); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
