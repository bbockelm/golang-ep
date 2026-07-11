module github.com/bbockelm/golang-ep

go 1.25.7

require (
	github.com/PelicanPlatform/classad v0.4.0
	github.com/PelicanPlatform/classad/collections v0.4.0
	github.com/bbockelm/cedar v0.3.0
	github.com/bbockelm/golang-htcondor v0.5.0
	golang.org/x/sys v0.46.0
)

require (
	github.com/RoaringBitmap/roaring/v2 v2.19.0 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/klauspost/compress v1.19.0 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/tidwall/btree v1.8.1 // indirect
)

require (
	github.com/bbockelm/golang-ap v0.0.0
	github.com/bbockelm/gosssd v0.0.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

// Build against the local checkouts so the EP tracks in-progress cedar,
// golang-htcondor, and classad changes (matching the developer's workspace).
replace github.com/bbockelm/cedar => /Users/bbockelm/projects/golang-cedar

replace github.com/bbockelm/golang-htcondor => /Users/bbockelm/projects/golang-htcondor

replace github.com/PelicanPlatform/classad => /Users/bbockelm/projects/golang-classads

replace github.com/PelicanPlatform/classad/collections => /Users/bbockelm/projects/golang-classads/collections

replace github.com/bbockelm/golang-ap => /Users/bbockelm/projects/golang-ap
