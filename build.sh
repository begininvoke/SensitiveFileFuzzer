#!/usr/bin/bash
archs=(amd64 arm64)
os=(linux windows darwin)

for o in ${os[@]}
do
for arch in ${archs[@]}
do
        env GOOS=${o} GOARCH=${arch} go build -o SensitiveFileFuzzer_${o}_${arch}
done
done
