documentation:
	cp README.md docs/_index.md
	cp README.md docs/README.md
	docker run -v `pwd`/docs:/input -v `pwd`/.docs:/output -it --rm michaeldonat/daux.io
