all: clean-all article.pdf clean

clean:
	rm -f *.aux *.dvi *.log *.ps *.bbl *.blg

article.pdf: article.tex
	pdflatex article.tex
	bibtex article
	pdflatex article.tex
	pdflatex article.tex

clean-all: clean
	rm -f *.pdf
