module github.com/vaudience/go-apikeys/examples/observability/basic

go 1.24

replace github.com/vaudience/go-apikeys/v2 => ../../..

require (
	github.com/itsatony/go-datarepository v0.0.0
	github.com/prometheus/client_golang v1.20.5
	github.com/vaudience/go-apikeys/v2 v2.1.0
	go.uber.org/zap v1.27.0
)
