reg-challenge:
	curl 'https://demo.yubico.com/wsapi/u2f/enroll?username=$(USER)&password=foo' | tee $@

reg: reg-challenge
	u2f-host -d -aregister -o https://demo.yubico.com < $< | tee $@.tmp
	curl https://demo.yubico.com/wsapi/u2f/bind -d "username=$(USER)&password=foo&data=`cat $@.tmp`" | tee binding

sign-challenge:
	curl 'https://demo.yubico.com/wsapi/u2f/sign?username=$(USER)&password=foo' | tee $@

auth: sign-challenge
	u2f-host -aauthenticate -o https://demo.yubico.com < $< | tee $@.tmp
	curl https://demo.yubico.com/wsapi/u2f/verify -d "username=$(USER)&password=foo&data=`cat $@.tmp`" | tee auth

.PHONY: sign-challenge reg-challenge auth
