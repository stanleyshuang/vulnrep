# vulnrep

## 執行前準備

創建以下設定檔，如果路徑不存在，請新增路徑：

$USER/srv/vulnrep/.$USER/credential.sh


內容如下：

### Environment variables of secret
export jira_url='https://qnap-jira.qnap.com.tw'

export jira_username='xxxx'

export jira_password="xxxx"


export salesforce_url='https://qnap.lightning.force.com/'

export salesforce_username='xxxx'

export salesforce_password='xxxx'

export salesforce_orgid='xxxx'<br>


export mantis_url='https://bugtracking.qnap.com.tw/api/soap/mantisconnect.php?wsdl'

export mantis_username='xxxx'

export mantis_password='xxxx'

export mantis_project='QTS 4.x'



## Get Started

到專案根目錄，依不同作業系統，執行以下指令：

./make.sh macos # for Macbook

./make.sh qts # for QNAP NAS


如果程式未安裝，執行後會完成安裝。接下來會類似看到以下的提示：


-- Run the following script 1 ----

source "[path to repo]/vulnrep/install/_build/macos/env.sh"

source "$USER/srv/vulnrep/.$USER/credential.sh"

cd $USER/srv/vulnrep

$USERsrv/vulnrep/scripts/run.sh

-- Run the following script 2 ----

source "[path to repo]/vulnrep/install/_build/macos/env.sh"

source "$USER/srv/vulnrep/.$USER/credential.sh"

cd $USER/srv/vulnrep

source $USER/srv/vulnrep/venv/bin/activate



複製貼上以執行 "-- Run the following script 2 ----" 以下命令，即可進入 python virtual environment。
執行程式如：

python main.py


