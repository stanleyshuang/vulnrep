#!/usr/bin/env bash
origin_path=$(pwd)
work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)
cd $origin_path

### Primary variables
srv_home="/Users/$USER/srv"
project="vulnrep"

### Environment variables directed from primary ones
export src=$base_dir/../../../app
export config=$base_dir/../../../base
export apphome=$srv_home/$project
