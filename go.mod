module github.com/Regan-Milne/obsideo-provider

go 1.22

require (
	github.com/dgraph-io/badger/v4 v4.2.0
	github.com/gorilla/mux v1.8.1
	github.com/json-iterator/go v1.1.12
	github.com/prometheus/client_golang v1.18.0
	github.com/rs/cors v1.11.0
	github.com/rs/zerolog v1.33.0
	github.com/spf13/cobra v1.8.0
	github.com/wealdtech/go-merkletree/v2 v2.6.0
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.23.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/flatbuffers v1.12.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/iden3/go-iden3-crypto v0.0.16 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)

replace (
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
	github.com/hsanjuan/ipfs-lite => github.com/TheMarstonConnell/ipfs-lite v0.0.0-20240304191454-94283a9ad1c9
	github.com/ipfs/go-ds-badger2 => github.com/TheMarstonConnell/go-ds-badger2 v0.0.0-20240304191516-af5ee03005fc
	github.com/wealdtech/go-merkletree/v2 => github.com/TheMarstonConnell/go-merkletree/v2 v2.0.0-20250829184252-ad65f46fbd22
)
