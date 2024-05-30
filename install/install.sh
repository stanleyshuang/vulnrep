#!/usr/bin/env bash
# work_path could be related path
# base_dir is the absolutely path
work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)
repo="$base_dir/.."
env="$base_dir/_build/$1"

### 0. Check arguments
# the configuration
if [ $# != 1 ]; then
    echo "!> Missing environment information." 
    echo "!> Usage: $0 <macos | qts>"
    exit
fi

# environment variables
if [ ! "$src" ] || [ ! "$config" ] || [ ! "$apphome" ]; then
  echo '!> Missing $src.' 
  echo "!> Run 'source $env/env.sh'"
  exit
fi

### 1. Make the file structure
# file structure
# $repo
#  |-- install ($base_dir)
#         |-- _build
#         |      |-- $env
#         |            |-- src: customized app home
#         |            |-- config: customized configuration
#         |            |-- env.sh
#         |-- install.sh
#
# $src: common app home
#
# $config: requirement.txt, docker images, and so on
#
# $apphome: copy from $src + $env/src

if [[ ! -d $apphome ]]; then
  echo "mkdir -p $apphome"
        mkdir -p $apphome
fi

# copy py_lib into the project
if [ -d "/Users/$USER/gitlab/stanleyshuang/py_lib" ]; then
echo "cp -a  /Users/$USER/gitlab/stanleyshuang/py_lib/pkg/.  $src/pkg/"
      cp -a "/Users/$USER/gitlab/stanleyshuang/py_lib/pkg/." $src/pkg/

echo "cp -a  /Users/$USER/gitlab/stanleyshuang/py_lib/tests/.  $src/tests/"
      cp -a "/Users/$USER/gitlab/stanleyshuang/py_lib/tests/." $src/tests/
fi

# update latest source code
echo "cp -a  $src/.  $apphome/"
      cp -a "$src/." $apphome/

if [ -d "$env/src" ]; then
  echo "cp -a  $env/src/.  $apphome/"
        cp -a "$env/src/." $apphome/
fi

echo "cp -a  $env/env.sh  $apphome/scripts/env.sh"
      cp -a "$env/env.sh" $apphome/scripts/env.sh

### 2. Create Python3 virtual environment
if ! [ -d "$apphome/venv" ]; then
  echo "python3 -m venv  $apphome/venv"
        python3 -m venv "$apphome/venv"
  echo "source  $apphome/venv/bin/activate"
        source "$apphome/venv/bin/activate"
  echo "pip install --upgrade pip"
        pip install --upgrade pip
  if [ -f "$env/config/requirements.txt" ]; then
    echo "pip install -r  $env/config/requirements.txt"
          pip install -r "$env/config/requirements.txt"
  elif [ -f "$config/requirements.txt" ]; then
    echo "pip install -r  $config/requirements.txt"
          pip install -r "$config/requirements.txt"
  fi
  echo "deactivate"
        deactivate
fi

### 3. Run script
echo "-- Run the following script 1 ----"
echo "source \"$env/env.sh\""
echo "source \"$apphome/.$USER/credential.sh\""
echo "cd $apphome"
echo "$apphome/scripts/run.sh"
echo "-- Run the following script 2 ----"
echo "source \"$env/env.sh\""
echo "source \"$apphome/.$USER/credential.sh\""
echo "cd $apphome"
echo "source $apphome/venv/bin/activate"
