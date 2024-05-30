# -*- coding: utf-8 -*-
#
# Author:   Stanley Huang
# Project:  util_text_file 1.0
# Date:     2024/01/31
#
import unittest
from pkg._util.util_text_file import html_2_text


class Html2TextTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_html_2_text_10(self):
        html_content = "<p>This is an example <b>HTML</b> content.</p>"
        plain_text = html_2_text(html_content)
        self.assertTrue(plain_text == "This is an example **HTML** content.\n\n")
