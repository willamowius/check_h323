PROG		= check_h323
SOURCES		= check_h323.cxx

ifndef OPENH323DIR
OPENH323DIR=$(HOME)/openh323
endif

include $(OPENH323DIR)/openh323u.mak

dist:
	mkdir -p check_h323
	cp -p Makefile readme.txt check_h323.cxx check_h323/
	tar cvzf check_h323.tar.gz check_h323/*
	zip -r check_h323.zip check_h323/*

