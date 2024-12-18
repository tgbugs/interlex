set -e
set -o xtrace
path=${1}
wd=$(dirname "${path}")
fn=$(basename "${path}")
stem="${fn%%.*}"
suffixes="${fn#*.}"

infile="${stem}".ntriples

pat_bnode_sub='^_:[^ ]\+ '
pat_bnode_obj=' _:[^ ]\+ \.$'
pat_bnode_link='^_:[^ ]\+ .\+ _:[^ ]\+ .$'
pat_bnode_trip='^_:[^ ]\+ \| _:[^ ]\+ .$'

pushd "${wd}"

test -e "${infile}" || { test -e edges && exit 0; }  # FIXME shortcircuit

# sadly we cannot use sort -V for this because it ignores leading zeros
# things like <01> <a> <x>  <1> <b> <x>  <01> <c> <x> sort intermixed
{ grep -v "${pat_bnode_trip}" "${infile}" || true; } | sort >                                                     "${stem}-name.ntriples"
{ grep "${pat_bnode_trip}" "${infile}" || true; } >                                                               "${stem}-bnode.ntriples"

# never trust a regex
{ grep "${pat_bnode_sub}" "${stem}-bnode.ntriples" | grep -v "${pat_bnode_obj}" || true; } \
       | sed 's/_:gen/ _:gen/' | sort -V --key=1.8 | sed 's/^ //' >                                               "${stem}-term.ntriples"  # (_ p o)
{ grep    "${pat_bnode_link}" "${stem}-bnode.ntriples" || true; } >                                               "${stem}-link.ntriples"  # (_ p _)
{ grep -v "${pat_bnode_sub}"  "${stem}-bnode.ntriples" || true; } >                                               "${stem}-conn.ntriples"  # (s p _)

wc -l "${stem}.ntriples" >                                                                                        "${stem}.count"
rm "${stem}.ntriples"  # save some space
wc -l "${stem}-bnode.ntriples" >                                                                                  "${stem}-bnode.count"
rm "${stem}-bnode.ntriples"  # save some space
wc -l "${stem}-name.ntriples" >                                                                                   "${stem}-named.count"
wc -l "${stem}-term.ntriples" >                                                                                   "${stem}-term.count"
wc -l "${stem}-link.ntriples" >                                                                                   "${stem}-link.count"
wc -l "${stem}-conn.ntriples" >                                                                                   "${stem}-conn.count"

cat "${stem}-name.ntriples" | cut -d'>' -f1 | sed 's/$/>/' | sort | uniq -c | sort -n >                           "${stem}-ncnt"
{ grep "${pat_bnode_trip}"   "${stem}-term.ntriples" || true; } | awk '{ print $1 }' | sort | uniq -c | sort -n > "${stem}-term-bscnt"
{ grep "${pat_bnode_trip}"   "${stem}-link.ntriples" || true; } | awk '{ print $1 }' | sort | uniq -c | sort -n > "${stem}-link-bscnt"
{ grep -o "${pat_bnode_obj}" "${stem}-link.ntriples" || true; } | awk '{ print $1 }' | sort | uniq -c | sort -n > "${stem}-link-bocnt"
{ grep -o "${pat_bnode_obj}" "${stem}-conn.ntriples" || true; } | awk '{ print $1 }' | sort | uniq -c | sort -n > "${stem}-conn-bocnt"
cat "${stem}-conn.ntriples" | cut -d'>' -f1 | sed 's/$/>/' | sort | uniq -c | sort -n >                           "${stem}-conn-nscnt"

cat "${stem}-link.ntriples" | sed 's/\(^_:[^ ]\+\) .\+ \(_:[^ ]\+\) \.$/\1 \2/' > edges
