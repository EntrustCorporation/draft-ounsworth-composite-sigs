docName:=draft-ounsworth-pq-composite-sigs

default: $(docName)/text

$(docName)/text:: $(docName).xml
	@xml2rfc $(docName).xml --html --text

$(docName).xml:
	@./insertFileIncludes.sh $(docName).md "." > $(docName)_tmp.md ; \
	   kramdown-rfc2629 $(docName)_tmp.md > $(docName).xml ; \
	   rm $(docName)_tmp.md
	@rm -f $(docName).txt $(docName).html 
	# Removing .html and .txt because they are mis-aligned.

clean:
	rm -f $(docName).xml
	# Explicitely not deleting the .html or .txt because that should be committed to git for other people's ease of editing.
