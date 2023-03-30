go test -v ./... -gcflags="-l" -cover


#go test -v -coverprofile cover.out                       
#go tool cover -html cover.out -o cover.html
# cd api && open cover.html
