TARGETS = smtp pop3 echoserver connections tokenizer email_file

all: $(TARGETS)

echoserver: echoserver.cc connections.cc
	g++ $^ -lpthread -g -o $@

smtp: smtp.cc connections.cc tokenizer.cc email_file.cc
	g++ $^ -lpthread -g -o $@

pop3: pop3.cc connections.cc tokenizer.cc email_file.cc
	g++ $^ -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto -lpthread -g -o $@

pack:
	rm -f submit-hw2.zip
	zip -r submit-hw2.zip *.cc *.h* README Makefile

clean::
	rm -fv $(TARGETS) *~

realclean:: clean
	rm -fv submit-hw2.zip
