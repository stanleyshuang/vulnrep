# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  util_file. 1.0
# Date:     2024/01/02
#
import unittest
from pkg._util.util_file import (
    extract_text_from_pdf,
    extract_text_from_word,
    unzip_and_get_file_paths,
)


class ExtractTextFromPdfTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_text_from_pdf_10(self):
        text_content = extract_text_from_pdf("./tests/sample.pdf")
        the_answer = ""
        with open("./tests/samplePdf.txt", "r") as file:
            the_answer = file.read()
        self.assertTrue(the_answer == text_content)


class ExtractTextFromWordTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_extract_text_from_word_10(self):
        text_content = extract_text_from_word("./tests/sample.docx")
        # with open('./tests/sampleWord.txt', 'w') as file:
        #     file.write(text_content)
        the_answer = ""
        with open("./tests/sampleWord.txt", "r") as file:
            the_answer = file.read()
        self.assertTrue(the_answer == text_content)


class UnzipAndGetFilePathsTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_unzip_and_get_file_paths_10(self):
        extracted_paths = unzip_and_get_file_paths("./tests/sample.zip", "./tests")
        self.assertTrue(
            str(extracted_paths)
            == "['./tests/sample/sampleWord.txt', './tests/sample/samplePdf.txt', './tests/sample/__MACOSX']"
        )
