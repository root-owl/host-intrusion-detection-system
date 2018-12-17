#!/bin/bash

set -o nounset
set -o errexit

remove_testData_func()
{
    sudo rm -rf /file*
    sudo rm -rf /folder*
}

copy_testData_func()
{
    sudo cp -a ./testData/* /
    sudo chown -hR ${USER}:${USER} /file*
    sudo chown -hR ${USER}:${USER} /folder*
}

recover_testData_func()
{
    remove_testData_func
    copy_testData_func
}

run_base_line_func()
{
    sudo ./aide -J 1 -i
    pushd /usr/local/etc/aideDB
    sudo mv aide.db.new.json aide.db.old.json
    sudo mv aide.db.new aide.db
    popd

    sudo ./aide -J 1 -i
    sudo ./aide -E
    pushd /usr/local/etc/aideDB
    echo "Sha512 of old JSON db"
    sha512sum aide.db.old.json
    echo "Sha512 of new JSON db"
    sha512sum aide.db.new.json
    popd
}

check_func()
{
    sudo ./aide -J 1 -i
    sudo ./aide -E
}

case $1 in
    remove) echo "Removing testing datas..."
        remove_testData_func
        ;;
    copy) echo "Copying testing datas..."
        copy_testData_func
        ;;
    recover) echo "Recovering testing datas..."
        recover_testData_func
        ;;
    baseline) echo "Running base line..."
        run_base_line_func
        ;;
    check) echo "Checking system..."
        check_func
        ;;
    *) echo "Unknown cmd: $1"
esac


