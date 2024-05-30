#!/usr/bin/env bash
script_path="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
log_location="$apphome/downloads/run"

if [[ ! -d $log_location ]]; then
  echo "mkdir -p $log_location"
        mkdir -p $log_location
fi

      exec > $log_location/$(date '+%Y%m%d_%H%M%S').txt 2>&1
echo "exec > $log_location/$(date '+%Y%m%d_%H%M%S').txt 2>&1"

echo "cd $apphome/"
      cd $apphome/

echo "source $apphome/venv/bin/activate"
          cd $apphome/
      source $apphome/venv/bin/activate
     
echo "python3 $apphome/main.py $1 $2 $3"
      python3 $apphome/main.py $1 $2 $3