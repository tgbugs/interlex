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
if [ "${rapper_input_type}" = "rdfxml" ]; then
    sed 's/rdf:nodeID="genid/rdf:nodeID="lgenid/g' "${fn}" > "${lbnode}"
    # FIXME TODO handle other input types
else
    ln -s "${fn}" "${lbnode}"
fi

rapper \
--feature normalizeLanguage=0 \
--feature noNet=1 \
--feature noFile=1 \
-i ${rapper_input_type} -o ntriples "${lbnode}" | sort -u > "${stem}".ntriples
# must use sort -u because rapper will produce dupes which breaks
# identities because everything after assume all triples are distinct

rm "${lbnode}" &

xz -e -9 "${fn}" &
