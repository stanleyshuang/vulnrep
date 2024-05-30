#!/usr/bin/env bash
### Primary variables
srv_home="/share/CACHEDEV1_DATA/srv"
project="vulnrep"
base_dir="/share/CACHEDEV1_DATA/runes/$project"

if ! [ $USER == "stanley" ]; then
        exec > $srv_home/$project/env.log 2>&1
  echo "exec > $srv_home/$project/env.log 2>&1"
fi
whoami

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

### Python3
if ! [[ ":$PATH:" == *":/opt/python3/bin/:"* ]]; then
  echo "export PATH=$PATH:/opt/python3/bin/"
        export PATH=$PATH:/opt/python3/bin/
fi

if ! [ -f /opt/python3/bin/pip ]; then
  echo ". /etc/profile.d/python3.bash"
        . /etc/profile.d/python3.bash
  py3=$(which python3)
  py3_dir="$(dirname "${py3}")"
  if ! [ -d /opt/python3/bin/ ]; then
    if ! [ -d /opt/python3/ ]; then
      sudo mkdir /opt/python3
    fi
    sudo mkdir /opt/python3/bin
  fi
  echo "sudo ln $py3_dir/pip3 /opt/python3/bin/pip"
        sudo ln $py3_dir/pip3 /opt/python3/bin/pip
  echo "sudo ln $py3_dir/pip3 /opt/python3/bin/pip3"
        sudo ln $py3_dir/pip3 /opt/python3/bin/pip3
fi

### crontab
if grep -q "$apphome/scripts/run.sh" "/etc/config/crontab"; then
  echo ""
else
  echo "echo \"1 14,20 * * 1-5 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update hour:6\" >> \"/etc/config/crontab\""
        echo  "1 14,20 * * 1-5 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update hour:6"  >>  "/etc/config/crontab"
  echo "echo \"1 6 * * * . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update hour:24 && $apphome/scripts/run.sh remind:7\" >> \"/etc/config/crontab\""
        echo  "1 6 * * * . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update hour:24 && $apphome/scripts/run.sh remind:7"  >>  "/etc/config/crontab"
  echo "echo \"1 19 * * 2,4 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update qsa && $apphome/scripts/run.sh update rn && $apphome/scripts/run.sh update overdue\" >> \"/etc/config/crontab\""
        echo  "1 19 * * 2,4 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update qsa && $apphome/scripts/run.sh update rn && $apphome/scripts/run.sh update overdue"  >>  "/etc/config/crontab"
  echo "echo \""1 3 * * 3,6 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update bounty_nomination\" >> \"/etc/config/crontab\""
        echo   "1 3 * * 3,6 . $apphome/scripts/env.sh && . $apphome/.$USER/credential.sh && $apphome/scripts/run.sh update bounty_nomination"  >>  "/etc/config/crontab"
  echo "sudo crontab /etc/config/crontab && sudo /etc/init.d/crond.sh restart"
        sudo crontab /etc/config/crontab && sudo /etc/init.d/crond.sh restart
  echo "sudo crontab -l | grep $project"
        sudo crontab -l | grep $project
fi