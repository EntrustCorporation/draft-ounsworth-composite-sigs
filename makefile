
docName = draft-ounsworth-pq-composite-sigs


default: all

txt: $(docName).txt

draft-ounsworth-pq-composite-sigs.txt: $(docName).mkd
	kdrfc $(docName).mkd



xml: $(docName).xml

draft-ounsworth-pq-composite-sigs.xml: $(docName).mkd
	 kramdown-rfc2629 $(docName).mkd > $(docName).xml



html: all # xml
	# xml2rfc $(docName).xml --basename $(docName) --html
 # Explicitely aliasing this to `all` so that a .txt is always generated, because that should be committed to git for other people's ease of editing.

all: xml
	xml2rfc $(docName).xml --html --text


clean:
	rm -f $(docName).xml $(docName).html # $(docName).txt
	# Explicitely not deleting the .txt because that should be committed to git for other people's ease of editing.
