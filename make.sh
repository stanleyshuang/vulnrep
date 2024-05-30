 #!/usr/bin/env bash

if [ $# != 1 ]; then
    echo "!> Missing environment information." 
    echo "!> Usage: $0 <macos | qts>"
    exit
fi
 source ./install/_build/$1/env.sh
 ./install/install.sh $1