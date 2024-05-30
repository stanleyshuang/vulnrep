#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  honey 1.0
# Date:     2022-02-04
#
import paramiko

class ssh():
    def __init__(self, username, password, hostname, port):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.port = port
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname, port, username, password)

            t = self.ssh.get_transport()
            self.sftp = paramiko.SFTPClient.from_transport(t)
        except Exception:
            print('!!! EXCEPTION: paramiko')
            raise

    def upload(self, local_path, target_path):
        # 連線，上傳
        self.sftp.put(local_path, target_path)

    def download(self, remote_path, local_path):
        self.sftp.get(remote_path, local_path)

    def cmd(self, command):
        # 執行命令
        stdin, stdout, stderr = self.ssh.exec_command(command)
        # 獲取命令結果
        result = stdout.read()
        # printf(str(result, encoding='utf-8'))
        return result
