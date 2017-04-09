#!/bin/bash

###############################################################################
######################## FUNCTIONS SECTION ####################################
###############################################################################

#the function that will be called when we are ready to renew the certs.
function run_renewcerts(){
    # cd certs/san/
    cd certs/
    echo ""
    #move the custom cnf into our working directory
    # cp renewcerts/wolfssl.cnf wolfssl.cnf
    cp san/wolfssl.cnf wolfssl.cnf

    # To generate these all in sha1 add the flag "-sha1" on appropriate lines
    # That is all lines beginning with:  "openssl req"

    ############################################################
    ########## update the self-signed ca-cert.pem ##############
    ############################################################
    echo "Updating ca-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\nMontana\nBozeman\nSawtooth\nConsulting\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ca-key.pem -nodes -out ca-cert.csr -config wolfssl.cnf

    openssl x509 -req -in ca-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ca-key.pem -out ca-cert.pem
    # rm ca-cert.csr

    openssl x509 -in ca-cert.pem -text > tmp.pem
    mv tmp.pem ca-cert.pem

    ############################################################
    ########## make .der files from .pem files #################
    ############################################################
    echo "Creating der formatted certs..."
    echo ""
    openssl x509 -inform PEM -in ca-cert.pem -outform DER -out ca-cert.der

#    echo "Changing directory to wolfssl root..."
#    echo ""
    cd ../
#    echo "Execute ./gencertbuf.pl..."
#    echo ""
#    ./gencertbuf.pl
    ############################################################
    ########## generate the new crls ###########################
    ############################################################

    echo "Change directory to wolfssl/certs"
    echo ""
    cd certs
    echo "We are back in the certs directory"
    echo ""

    echo "Updating the crls..."
    echo ""
    cd crl
    echo "changed directory: cd/crl"
    echo ""
#    ./gencrls.sh
#    echo "ran ./gencrls.sh"
#    echo ""

    #cleanup the file system now that we're done
    echo "Performing final steps, cleaning up the file system..."
    echo ""

    # rm ../wolfssl.cnf

}

#function for restoring a previous configure state
function restore_config(){
    mv tmp.status config.status
    mv tmp.options.h wolfssl/options.h
    make clean
    make -j 8
}

#function for copy and pasting ntru updates
function move_ntru(){
    cp ntru-cert.pem certs/ntru-cert.pem
    cp ntru-key.raw certs/ntru-key.raw
    cp ntru-cert.der certs/ntru-cert.der
}


#start in root.
cd ../
run_renewcerts

