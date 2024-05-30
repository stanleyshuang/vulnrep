#!/usr/bin/env bash

### Primary variables
srv_home="/Users/$USER/srv"
script_path="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
if [[ $(basename $0) == 'env.sh' ]]; then
  project="$(basename "$(dirname "$(dirname "$(dirname "$script_path")")")")"
  base_dir="$script_path/../../.."
else
  project="$(basename "$script_path")"
  base_dir="$script_path"
fi

echo '### Primary variables'
echo 'srv_home: ' $srv_home
echo 'project: ' $project
echo 'base_dir: ' $base_dir

### Environment variables directed from primary ones
export src=$base_dir/app
export config=$base_dir/base
export apphome=$srv_home/$project

echo '### Environment variables directed from primary ones'
echo 'src: ' $src
echo 'config: ' $config
echo 'apphome: ' $apphome
