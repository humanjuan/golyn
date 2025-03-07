echo "================================ Compile Golang Server to Linux OS ================================"
rootPath=$(cd "$(dirname "$0")/.." && pwd)
buildPath="$rootPath"/builds

version=$(grep 'version' "$rootPath"/cmd/golyn.go | gsed -n 's/.*version.*= *"\(v[0-9]\+\.[0-9]\+\.[0-9]\+\(-[0-9]\+\w\)\?\)".*/\1/p')
name="Golyn"
releaseName="$name"_"$version"
releaseNameNoVersion="$name"
releaseNote=$releaseName"_release_note.txt"

rm -rf releaseName releaseName.tar.gz

echo "Creating directory structure..."
mkdir "$buildPath"/"$releaseNameNoVersion"
mkdir "$buildPath"/"$releaseNameNoVersion"/var
mkdir "$buildPath"/"$releaseNameNoVersion"/var/log
mkdir "$buildPath"/"$releaseNameNoVersion"/config
mkdir "$buildPath"/"$releaseNameNoVersion"/config/server
mkdir "$buildPath"/"$releaseNameNoVersion"/config/sites
mkdir "$buildPath"/"$releaseNameNoVersion"/certificates
mkdir "$buildPath"/"$releaseNameNoVersion"/certificates/golyn
mkdir "$buildPath"/"$releaseNameNoVersion"/sites


echo "[OK] Directory structure"

echo "Copying files..."
cp -R "$rootPath"/sites/golyn "$buildPath"/"$releaseNameNoVersion"/sites
cp "$rootPath"/config/server/*.conf "$buildPath"/"$releaseNameNoVersion"/config/server
cp "$rootPath"/config/sites/*.conf "$buildPath"/"$releaseNameNoVersion"/config/sites

echo "[OK] Copied files"

echo "Compiling..."
CGO_ENABLED=0 GOARCH=amd64 GOOS=darwin go build -ldflags="-s -w" -o "$buildPath"/"$releaseNameNoVersion"/golyn "$rootPath"/cmd/golyn.go
echo "[OK] Compiled"

echo "Compressing binary..."
upx --best --lzma "$buildPath"/"$releaseNameNoVersion"/golyn
echo "[OK] Compressed"

echo "Generating $releaseNote"
nowDT=$(date +"%Y-%m-%d %H:%M:%S")
echo "Release: $name $version (Linux) $nowDT" >  "$buildPath"/"$releaseNameNoVersion"/"$releaseNote"

printf "\n| %-30s | %-30s | %-30s\n" " File Name" "Last Update" "Hash MD5" >> "$buildPath"/"$releaseNameNoVersion"/"$releaseNote"
echo "-------------------------------------------------------------------------------------------------------" >> "$buildPath"/"$releaseNameNoVersion"/"$releaseNote"


cmd="$rootPath"/cmd
internal="$rootPath"/internal
modules_path="$rootPath"/modules
app="$rootPath"/app
test="$rootPath"/test

if [ -d "$rootPath" ]; then
    for folder in "$rootPath"/*; do
        if [ -d "$folder" ]; then
            if [ "$folder" = "$cmd" ] || [ "$folder" = "$internal" ] || [ "$folder" = "$modules_path" ] || [ "$folder" = "$app" ] || [ "$folder" = "$test" ]; then
                for archivo in "$folder"/*.go; do
                    if [ -f "$archivo" ]; then
                        timestamp=$(stat -t "%Y-%m-%d %H:%M:%S" -f "%Sm" "$archivo")
                        name=$(basename "$archivo")
                        hash=$(md5 -q "$archivo")
                        printf "| %-30s | %-30s | %-30s\n" "$name" "$timestamp" "$hash" >> "$buildPath"/"$releaseNameNoVersion"/"$releaseNote"
                    fi
                done
            fi
        fi
    done
else
    echo "The directory does not exist: $rootPath"
fi

echo "[OK] $releaseNote"

# Remover archivos `._*` y atributos extendidos de macOS
echo "Removing macOS metadata files..."
find "$buildPath" -name '._*' -delete
xattr -rc "$buildPath/$releaseNameNoVersion" 2>/dev/null
echo "[OK] macOS metadata files removed"

# Crear el paquete tar.gz sin atributos extendidos
echo "Packaging..."
cd "$buildPath" && bsdtar --no-xattrs -czvf "${releaseName}_linux.tar.gz" "$releaseNameNoVersion"
if [ $? -ne 0 ]; then
    echo "[ERROR] Packaging failed!"
    exit 1
fi

# Verificar el contenido del archivo comprimido
echo "Verifying tarball contents..."
tar -tzvf "$buildPath/${releaseName}_linux.tar.gz"
echo "[OK] Tarball contents verified"

echo "Ready! :) --> $tar"


