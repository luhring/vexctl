package formats

// TODO: we might not need this file

type Filterable interface {
	Filter()
}

type Selection[T any] interface {
	WherePackageName(string) Selection[T]
	WherePackageURL(string) Selection[T]
	WhereVulnerabilityID(string) Selection[T]
	WherePackageID(string) Selection[T] // i.e. package SPDX ID
}

type ScanDocument interface {
}
