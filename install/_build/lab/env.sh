#!/usr/bin/env bash
origin_path=$(pwd)
work_path=$(dirname $0)
cd $work_path
base_dir=$(pwd)
cd $origin_path

### Primary variables
srv_home="/Users/$USER/srv"
script_path="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
project="$(basename $(dirname $(dirname $(dirname $script_path))))"

echo '### Primary variables'
echo 'srv_home: ' $srv_home
echo 'project: ' $project

### Environment variables directed from primary ones
export src=$base_dir/../../../app
export config=$base_dir/../../../base
export apphome=$srv_home/$project

echo '### Environment variables directed from primary ones'
echo 'src: ' $src
echo 'config: ' $config
echo 'apphome: ' $apphome
