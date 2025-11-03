module github.com/vaudience/go-apikeys/examples/observability/custom-provider

go 1.24

replace github.com/vaudience/go-apikeys/v2 => ../../..

require (
	github.com/itsatony/go-datarepository v0.0.0
	github.com/vaudience/go-apikeys/v2 v2.1.0
	go.uber.org/zap v1.27.0
)
