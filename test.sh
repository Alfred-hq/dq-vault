go test -v ./... -gcflags="-l" -cover


go test -v -coverprofile cover.out -gcflags="-l"

go test -gcflags="-l" -cover -coverpkg=github.com/ryadavDeqode/dq-vault/api -v

# exclude (){
#     while read p || [ -n "$p" ]
#     do
#         sed -i '' "/${p//\//\\/}/d" ./coverage.out
#     done < ../exclude-from-code-coverage.txt
    
# }

go tool cover -html cover.out -o cover.html


# go test -gcflags="-l" ./... -cover
# -coverprofile=coverage.out && $(exclude) && go tool cover -html=coverage.out 

