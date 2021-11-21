# clean the mod cache
#go clean -modcache
# set the minimum go version to use for the module
go mod edit -go=1.16
# add missing and remove unused modules
go mod tidy
# update all dependencies
go get -u ./...
