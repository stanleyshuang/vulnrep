#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  Duffy ver. 2.0
# Date:     2017/12/15
#
import errno, gzip, json, os, re, sys
from pathlib import Path


def create_folder(folder):
    if not os.path.isdir(folder):
        Path(folder).mkdir(parents=True, exist_ok=True)


def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:  # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
            raise  # re-raise exception if a different error occured


def clean_local_folder(dir):
    for the_file in os.listdir(dir):
        file_path = os.path.join(dir, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(e)


def get_name_list_of_files(dir):
    files = [f for f in os.listdir(dir) if os.path.isfile(os.path.join(dir, f))]
    return files


def get_sub_folder_list(dir):
    sub_folders = [
        f for f in os.listdir(dir) if not os.path.isfile(os.path.join(dir, f))
    ]
    return sub_folders


def open_gzip_json(filename):
    return open_gzipfile_with_single_json(filename)


def open_gzip_multi_json(filename):
    return open_gzipfile_with_multi_line_json(filename)


def open_gzipfile_with_single_json(filename):
    data = None
    with gzip.open(filename, "rb") as f:
        file_content = f.read()
        try:
            data = json.loads(file_content)
        except ValueError as e:
            print(
                "\t\texception [ValueError] at parsing [{filename}]".format(
                    filename=filename
                )
            )
            data = None
    return data


def open_gzipfile_with_multi_line_json(filename):
    data = []
    with gzip.open(filename, "rb") as f:
        file_contents = f.readlines()
        for file_content in file_contents:
            try:
                data.append(json.loads(file_content))
            except ValueError as e:
                print(
                    "\t\texception [ValueError] at parsing [{filename}]".format(
                        filename=filename
                    )
                )
                data = None
    return data


def pgp_decrypt(passphrase, private_key_file, the_target_file):
    ### gpg --passphrase 'the_passphrase' -o output_file -d target_file
    ### gpg --list-secret-keys
    import gnupg

    # 创建GnuPG对象
    gpg = gnupg.GPG()

    # 导入PGP私钥和密码短语
    if private_key_file and len(private_key_file) > 0:
        private_key_data = open(private_key_file, "rb").read()
        # 导入私钥
        gpg.import_keys(private_key_data)

    temp_filename = the_target_file + ".decrypt"
    output_filename = (
        the_target_file.replace(".pgp", "").replace(".gpg", "").replace(".asc", "")
    )
    with open(the_target_file, "rb") as f:
        status = gpg.decrypt_file(f, passphrase=passphrase, output=temp_filename)
        if status.ok:
            os.rename(temp_filename, output_filename)
        else:
            print("!!! 解碼失敗 !!! " + the_target_file)
            print("!!! ok: ", status.ok)
            print("!!! status: ", status.status)
            print("!!! stderr: ", status.stderr)
        return status, output_filename
    return None, None


def extract_text_from_pdf(pdf_path):
    import fitz  # PyMuPDF

    try:
        # Open the PDF file
        pdf_document = fitz.open(pdf_path)
        # Initialize an empty string to store the extracted text
        text_content = ""
        # Iterate through each page in the PDF
        for page_number in range(pdf_document.page_count):
            # Get the page
            page = pdf_document[page_number]
            # Extract text from the page
            page_text = page.get_text()
            # Append the extracted text to the result
            text_content += page_text
        # Close the PDF document
        pdf_document.close()
        return text_content
    except Exception as e:
        print(f"Error: {e}")
        return None


def extract_text_from_word(docx_path):
    from docx import Document

    # Create a Document object
    doc = Document(docx_path)
    # Initialize an empty string to store extracted text
    extracted_text = ""
    # Iterate through paragraphs and add text to the string
    for paragraph in doc.paragraphs:
        extracted_text += paragraph.text + "\n"
    return extracted_text


def unzip_and_get_file_paths(zip_file_path, extract_to_path):
    import zipfile
    import os
    import shutil

    # Extract folder name from the zip file name
    folder_name = os.path.splitext(os.path.basename(zip_file_path))[0]

    # Create the folder or remove it if it already exists
    extract_folder_path = os.path.join(extract_to_path, folder_name)
    if os.path.exists(extract_folder_path):
        shutil.rmtree(extract_folder_path)
    os.makedirs(extract_folder_path)

    try:
        # Open the zip file
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            # Extract all the contents into the specified folder
            zip_ref.extractall(extract_folder_path)

        # Get the list of file paths for the extracted files
        extracted_file_paths = [
            os.path.join(extract_folder_path, file)
            for file in os.listdir(extract_folder_path)
        ]

        return extracted_file_paths
    except Exception as e:
        print("    解壓縮失敗：" + str(e))
        return []
