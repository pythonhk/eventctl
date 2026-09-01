module github.com/pythonhk/eventctl

go 1.26.0

toolchain go1.26.5

retract [v1.0.0, v1.0.1] // Superseded protocol line; use v0.3.1.

require (
	filippo.io/age v1.3.1
	github.com/caarlos0/env/v11 v11.4.1
	github.com/samber/lo v1.53.0
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.31.0 // indirect
)
