#!/bin/sh -ex

# To make the time-signed jars
# set $TSA1_URL, $TSA2_URL and $EXPIRED_TSA_URL  in the ./generate.conf file
#

[ -f ./generate.conf ] && . ./generate.conf

if [ ! -f input.jar ] ; then
	dir=$(mktemp -d tmp.XXXXXXXXXX) || exit 1
	cd $dir || exit 1
	echo "one" > one.txt
	echo "two" > two.txt
	mkdir dir
	echo "three" dir/three.txt
	jar cf ../input.jar *
	cd ..
        rm -r "$dir"
fi

if [ ! -f sign1.jar ] ; then
	cp input.jar sign1.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 sign1.jar sign1
fi

if [ ! -f sign2.jar ] ; then
	cp input.jar sign2.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 sign2.jar sign2
fi

if [ ! -f bad_sign.jar ] ; then
	cp input.jar bad_sign.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 bad_sign.jar bad_sign
fi

if [ ! -f expired_sign.jar ] ; then
	cp input.jar expired_sign.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 expired_sign.jar expired_sign
fi

if [ ! -f sign1_tsa1.jar -a -n "$TSA1_URL" ] ; then
	cp input.jar sign1_tsa1.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA1_URL" sign1_tsa1.jar sign1
fi

if [ ! -f sign1_tsa2.jar -a -n "$TSA2_URL" ] ; then
	cp input.jar sign1_tsa2.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA2_URL" sign1_tsa2.jar sign1
fi

if [ ! -f sign1_bad_tsa.jar -a -n "$BAD_TSA_URL" ] ; then
	cp input.jar sign1_bad_tsa.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$BAD_TSA_URL" sign1_bad_tsa.jar sign1
fi

if [ ! -f sign1_expired_tsa.jar -a -n "$EXPIRED_TSA_URL" ] ; then
	cp input.jar sign1_expired_tsa.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$EXPIRED_TSA_URL" sign1_expired_tsa.jar sign1
fi

if [ ! -f expired_sign_tsa1.jar -a -n "$TSA1_URL" ] ; then
	cp input.jar expired_sign_tsa1.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA1_URL" expired_sign_tsa1.jar expired_sign
fi

if [ ! -f expired_ca_sign_tsa1.jar -a -n "$TSA1_URL" ] ; then
	cp input.jar expired_ca_sign_tsa1.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA1_URL" expired_ca_sign_tsa1.jar expired_ca_sign
fi

if [ ! -f expired_sign_tsa2.jar -a -n "$TSA2_URL" ] ; then
	cp input.jar expired_sign_tsa2.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA2_URL" expired_sign_tsa2.jar expired_sign
fi

if [ ! -f expired_ca_sign_tsa2.jar -a -n "$TSA2_URL" ] ; then
	cp input.jar expired_ca_sign_tsa2.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$TSA2_URL" expired_ca_sign_tsa2.jar expired_ca_sign
fi


if [ ! -f expired_sign_expired_tsa.jar -a -n "$EXPIRED_TSA_URL" ] ; then
	cp input.jar expired_sign_expired_tsa.jar
	jarsigner -keystore ../certs/all.jks -storepass 123456 -tsa "$EXPIRED_TSA_URL" expired_sign_expired_tsa.jar expired_sign
fi





