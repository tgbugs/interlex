set -e
path=${1}
wd=$(dirname "${path}")
fn=$(basename "${path}")
stem="${fn%%.*}"
suffixes="${fn#*.}"
lbnode="${stem}-bnode-fix.${suffixes}"
rapper_input_type=${2}

pushd "${wd}"

stat --format='%s' "${fn}" > "${fn}".size-bytes
sha256sum "${fn}" > "${fn}".sha256
sed 's/rdf:nodeID="genid/rdf:nodeID="lgenid/g' "${fn}" > "${lbnode}"
rapper -i ${rapper_input_type} -o ntriples "${lbnode}" > "${stem}".ntriples

rm "${lbnode}" &

xz -e -9 "${fn}" &
