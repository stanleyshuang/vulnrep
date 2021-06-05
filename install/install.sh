#!/usr/bin/env bash
work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)
repo="$base_dir/.."
env="$base_dir/_build/$1"

### 1. Make the file structure
### 2. Create Python3 virtual environment

### 0. Check arguments
# the configuration
if [ $# != 1 ]; then
    echo "!> Missing environment information." 
    echo "!> Usage: $0 <lab | stg | pro>"
    exit
fi

# environment variables
if [ ! $src ] || [ ! $config ] || [ ! $apphome ]; then
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

# update latest source code
echo "cp -a $src/. $apphome/"
      cp -a $src/. $apphome/

if [ -d "$env/src" ]; then
  echo "cp -a $env/src/. $apphome/"
        cp -a $env/src/. $apphome/
fi

### 2. Create Python3 virtual environment
if ! [ -d "$apphome/venv" ]; then
  echo "python3 -m venv $apphome/venv"
        python3 -m venv $apphome/venv
  echo "source $apphome/venv/bin/activate"
        source $apphome/venv/bin/activate
  echo "pip install --upgrade pip"
        pip install --upgrade pip
  if [ -f "$env/config/requirements.txt" ]; then
    echo "pip install -r $env/config/requirements.txt"
          pip install -r $env/config/requirements.txt
  elif [ -f "$config/requirements.txt" ]; then
    echo "pip install -r $config/requirements.txt"
          pip install -r $config/requirements.txt
  fi
  echo "deactivate"
        deactivate
fi

### Run script
echo "-- Run the following script ----"
echo "cd $apphome/"
echo "source $apphome/venv/bin/activate"
echo "source ./credential.sh"
echo "python main.py"
