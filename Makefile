.PHONY: gen
gen: 
	plantuml -tsvg doc/protocol-run.puml
	plantuml -tsvg doc/communication.puml

