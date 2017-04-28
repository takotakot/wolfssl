#!/bin/sh

TMP="/tmp/`basename $0`"

gen_cert() {
    openssl req -x509 -keyform DER -key certs/server-key.der \
                      -outform DER -out $OUT -config $CONFIG \
        >$TMP 2>&1

    if [ "$?" = "0" -a -f $OUT ]; then
        echo "Created: $OUT"
    else
        cat $TMP
        echo "Failed:  $OUT"
    fi

    rm $TMP
}

gen_pem() {
    if [ -f $OUT ]; then
        openssl x509 -inform DER -in $OUT -text >$PEM
        if [ "$?" = "0" -a -f $PEM ]; then
            echo "Created: $PEM"
        else
            echo "Failed:  $PEM"
        fi
    else
        echo "Not exist:  $OUT"
    fi
}

OUT=certs/test/cert-ext-nc.der
CONFIG=certs/test/cert-ext-nc.cfg
PEM=${OUT%.der}.pem
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@www.wolfsssl.com

[ v3_ca ]
nameConstraints = critical,permitted;email:.wolfssl.com
nsComment       = "Testing name constraints"

EOF
gen_cert
gen_pem

OUT=certs/test/cert-ext-ia.der
CONFIG=certs/test/cert-ext-ia.cfg
PEM=${OUT%.der}.pem
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@www.wolfsssl.com

[ v3_ca ]
inhibitAnyPolicy = critical,1
nsComment        = "Testing inhibit any"

EOF
gen_cert
gen_pem

OUT=certs/test/cert-ext-san.der
CONFIG=certs/test/cert-ext-san.cfg
PEM=certs/test/cert-ext-san.pem
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@www.wolfsssl.com

[ v3_ca ]
subjectAltName   = @alt_names
nsComment        = "Testing SAN"

[alt_names]
DNS.1         = san1.wolfssl.com
DNS.2         = san2.wolfssl.com
email         = san@wolfssl.com
URI           = http://san1.wolfssl.com/example-path/

EOF
gen_cert
gen_pem

