module github.com/polynetwork/poly-relayer

go 1.15

require (
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.9.25
	github.com/go-redis/redis/v8 v8.11.3
	github.com/joeqian10/neo-gogogo v1.4.0
	github.com/ontio/ontology v1.14.1-alpha
	github.com/ontio/ontology-crypto v1.2.1
	github.com/ontio/ontology-go-sdk v1.12.4
	github.com/polynetwork/bridge-common v0.0.18-ont
	github.com/polynetwork/poly v1.3.1
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114035303-84e1615f4ad4
	github.com/rain-zxn/ontology-go-sdk v1.1.1
	github.com/urfave/cli/v2 v2.3.0
)

replace github.com/ontio/ontology => github.com/ontio/ontology v1.14.0-beta.0.20210818114002-fedaf66010a7
