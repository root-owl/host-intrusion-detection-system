#!/bin/bash

set -o nounset
set -o errexit

AIDE_VERSION="0.16"
AIDE_INSTALL_PREFIX="/usr/local"


build_from_source_func()
{
    set -x
    sudo apt-get install libgcrypt*

    ./configure --prefix=${AIDE_INSTALL_PREFIX}
    make

    set +x

    echo ""
    echo ""
    echo "Checking aide installation:"
    ./src/aide -v
}

install_from_source_func()
{
    set -x
    sudo apt-get install libgcrypt*

    ./configure --prefix=${AIDE_INSTALL_PREFIX}
    make
    sudo make install

    set +x

    echo ""
    echo ""
    echo "Checking aide installation:"
    aide -v
}

uninstall_from_source_func()
{
    set -x
    sudo make uninstall
    make clean
    make distclean
    set +x
}

tips_func()
{
    echo ""
    echo ""
    echo "User gudie for deployment:"
    echo "http://aide.sourceforge.net/stable/manual.html"
    echo ""
    echo ""
    echo "1) Checking aide version:"
    echo "sudo aide -v"

    echo "2) Init database:"
    echo "sudo aide --init"
    echo "sudo mv /path/to/aide.db.new /path/to/aide.db"

    echo "3) Check with database:"
    echo "sudo aide --check"

    echo "4) Update database"
    echo "sudo aide --update"
    echo "sudo mv /path/to/aide.db.new /path/to/aide.db"

}


case $1 in
    make) echo "Building AIDE from source..."
        make
        ./aide -v
        ;;
    config) echo "Configuring AIDE from source..."
        ./configure --prefix=${AIDE_INSTALL_PREFIX}
        ;;
    buildFromSrc) echo "Building AIDE from source..."
        build_from_source_func
        ;;
    installFromSrc) echo "Installing AIDE from source..."
        install_from_source_func
        ;;
    uninstallFromSrc) echo "Uninstalling AIDE from source..."
        uninstall_from_source_func
        ;;
    tips) echo "Using tips:"
        tips_func
        ;;
    *) echo "Unknown cmd: $1"
esac


