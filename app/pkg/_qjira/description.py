#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Auther:   Stanley Huang
# Project:  vulnrep 1.0
# Date:     2021-06-05
#
###############################################################################
### common functions
import re


def extract_str_in_link_v1(content):
    # regex to extract required strings
    sf_num_reg = r"(Q-\d{6}-\d{5})"
    m = re.search(sf_num_reg, content)
    sf_num = ""
    if m and m.group(1):
        sf_num = m.group(1)

    reg_str = r"\[(.*?)\]"
    in_bracket = re.search(reg_str, content)
    if in_bracket:
        res = in_bracket.group(1).split("|")
        if not res or len(res) == 0:
            return False, sf_num, "", content
        elif len(res) == 1:
            if res[0].find("http") >= 0:
                return True, sf_num, res[0], content[in_bracket.end() :]
            else:
                return True, sf_num, "", content[in_bracket.end() :]
        if len(res) == 2:
            return False, sf_num, res[1], content[in_bracket.end() :]
        return True, sf_num, res[len(res) - 1], content[in_bracket.end() :]
    return False, sf_num, "", content


def extract_str_in_link(content):
    pattern = r"^(.*?)\[(Q-\d{6}-\d{5})\|(https://qnap.lightning.force.com/lightning/r/Case/.*/view)\](.*?)$"
    m = re.search(pattern, content, re.DOTALL)
    if m:
        head = m.group(1)
        sf_num = m.group(2)
        url = m.group(3)
        tail = m.group(4)
        return False, sf_num, url, head + tail
    else:
        return extract_str_in_link_v1(content)


###############################################################################
### specific funstions
def parse_salesforce_link(content):
    b_need_update, name, link, others = extract_str_in_link(content)
    return b_need_update, name, link, others


def extract_model(content):
    """
    example:    [INTSI000-1025][Web][Security][Medium][V3] User Account hacking -> https://license2.qnap.com (Mark Ella)
    return:     Web
    """
    tokens = re.split("\[|\]", content)
    for token in tokens:
        if token.lower() in [
            "security",
            "v1",
            "v2",
            "v3",
            "v4",
            "v5",
            "info",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            continue
        elif token.lower().find("intsi000-") >= 0:
            continue
        elif token.lower().find("mantis#") >= 0:
            continue
        elif token.lower().find("sf:") >= 0:
            continue
        elif token is None or len(token) == 0 or token.isspace():
            continue
        elif (
            token.lower().find("qts") >= 0
            or token.lower().find("generic 5.") >= 0
            or token.lower().find("elecom") >= 0
        ):  # QTS
            return "qts", token, qts_version_begin(token)
        elif token.lower().find("quts hero") >= 0:  # QuTS hero
            return "quts hero", token, hero_version_begin(token)
        elif (
            token.lower().find("qutscloud") >= 0
            or token.lower().find("quts cloud") >= 0
        ):  # QuTScloud
            return "qutscloud", token, cld_version_begin(token)
        elif (
            token.lower().find("qnap cloud service") >= 0
            or token.lower().find("cloud web") >= 0
        ):  # QNAP Cloud Service
            return "qnap cloud service", token, cloudweb_version_begin(token)
        elif token.lower().find("amiz") >= 0:  # Amiz Cloud
            return "amiz", token, cloudweb_version_begin(token)
        elif token.lower().find("qpkg:") >= 0:  # QPKG
            return "qpkg", token.split(":")[1].strip(), "x"
        elif token.lower().find("mobile:") >= 0:  # mobile
            return "mobile", token.split(":")[1].strip(), "x"
        elif token.lower().find("android:") >= 0:  # Android
            return "android", token.split(":")[1].strip(), "x"
        elif token.lower().find("ios:") >= 0:  # iOS
            return "ios", token.split(":")[1].strip(), "x"
        elif token.lower().find("utility:") >= 0:  # Utility
            return "utility", token.split(":")[1].strip(), "x"
        elif token.lower().find("windows utility:") >= 0:  # Windows Utility
            return "windows utility", token.split(":")[1].strip(), "x"
        elif token.lower().find("macos utility:") >= 0:  # macOS Utility
            return "macos utility", token.split(":")[1].strip(), "x"
        elif (
            token.lower().find("qnap website") >= 0
            or token.lower().find("qnapwebsite") >= 0
            or token.lower() == "web"
        ):  # QNAP Website
            return "qnap website", token, qnapwebsite_version_begin(token)
        elif (
            token.lower().find("iei website") >= 0
            or token.lower().find("ieiwebsite") >= 0
        ):  # IEI Website
            return "iei website", token, ieiwebsite_version_begin(token)
        elif (
            token.lower().find("qne") >= 0
            or token.lower().find("qucpe") >= 0
            or token.lower().find("qgd") >= 0
            or token.lower().find("adra global") >= 0
        ):  # QNE
            return "qne", token, qne_version_begin(token)
        elif token.lower().find("qvp") >= 0:  # QVP
            return "qvp", token, qvp_version_begin(token)
        elif token.lower().find("qvr") >= 0:  # QVR
            return "qvr", token, qvr_version_begin(token)
        elif token.lower().find("qes") >= 0:  # QES
            return "qes", token, qes_version_begin(token)
        elif token.lower().find("quwan") >= 0:  # QuWAN
            return "quwan", token, wuwanwebsite_version_begin(token)
        elif token.lower().find("qmiro") >= 0:  # QuWAN
            return "qmiro", token, qumiro_version_begin(token)
        elif token.lower() == "main":  # Main
            return "main", token, "x"
        elif token.lower() == "misc":  # Misc.
            return "misc", token, "x"
        else:
            print('~~~ [extract_model] TAG: "' + token + '"')
            continue
    print("??? [extract_model] nothing found return None")
    return None, None, None


def extract_severity_level(content):
    """
    example:    [INTSI000-1025][Web][Security][Medium][V3] User Account hacking -> https://license2.qnap.com (Mark Ella)
    return:     [V3]
    """
    m = re.search(r"([\[][V][1-5][\]])", content)
    if m:
        return m.group(0)
    return None


def extract_cveid(content):
    """
    example:    [QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 | CVE-2021-28816 (xxyantixx)
    return:     CVE-2021-28815 | CVE-2021-28816
    """
    cvdids = []
    while True:
        m = re.search(r"(CVE-\d{4}-\d{4,7})", content)
        if m:
            cvdid = m.group(0)
            cvdids.append(cvdid)
            content = content.replace(cvdid, "")
        else:
            break
    if len(cvdids) > 0:
        return cvdids
    return None


def extract_cweid(content):
    """
    example:    CWE-798 Use of Hard-coded Credentials
    return      CWE-798
    """
    output = []
    content_list = content.split(",")
    for item in content_list:
        m = re.search(r"(CWE-\d{2,4})", item)
        if m:
            output.append(m.group(1))
    return sorted(output)


def extract_capecid(content):
    """
    example:    CAPEC-36 Use of Hard-coded Credentials
    return      CAPEC-36
    """
    output = []
    content_list = content.split(",")
    for item in content_list:
        m = re.search(r"(CAPEC-\d{2,4})", item)
        if m:
            output.append(m.group(1))
    return sorted(output)


def extract_quality_score(keyword, content):
    """
    example:    Description (描述的品質)： 5
                POC (概念性證明的品質)： 5
                Suggestion (修復建議的品質)： 5
    return      description: 5
                poc: 5
                suggestion: 5
    """
    m = re.search(
        r"({keyword}).*([1-5])".format(keyword=keyword.lower()), content.lower()
    )
    if m and m.group(1) and m.group(2):
        return int(m.group(2))
    return None


def extract_cvss_score(content):
    """
    example:    CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N (7.6)
                CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N (2.4)
                CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P (0.9)
    return:     CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N, 7.6
    """
    m = re.search(
        r"(CVSS:4.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN](?:\/E:[XAPU])?)\D*(\d{1}.\d{1})",
        content,
    )
    if m:
        return m.group(1), m.group(2), True
    
    m = re.search(
        r"(CVSS:4.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN](?:\/E:[XAPU])?)",
        content,
    )
    if m:
        return m.group(1), None, True



    m = re.search(
        r"(CVSS:3.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HLN]\/I:[HLN]\/A:[HLN])\D*(\d{1}.\d{1})",
        content,
    )
    if m:
        return m.group(1), m.group(2), False

    m = re.search(
        r"(CVSS:3.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HLN]\/I:[HLN]\/A:[HLN])",
        content,
    )
    if m:
        return m.group(1), None, False


    if content.lower().find("cvssv3 score") >= 0 or content.lower().find("cvss score") >= 0:
        m = re.search(r"cvssv.*(\d{1}\.\d{1})", content.lower())
        if m:
            return None, m.group(1), False

    if content.lower().find("cvssv4 score") >= 0 or content.lower().find("cvssv4 base + threat score") >= 0 or content.lower().find("cvss score") >= 0:
        m = re.search(r"cvssv.*(\d{1}\.\d{1})", content.lower())
        if m:
            return None, m.group(1), True

    return None, None, None


def extract_cvssv3_attr(content):
    """
    example:    CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N
                CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    return:     N, L ,L, R, C, H, L, N
    """
    m = re.search(
        r"CVSS:3.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])",
        content,
    )
    if m:
        return (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4),
            m.group(5),
            m.group(6),
            m.group(7),
            m.group(8),
        )
    return None, None, None, None, None, None, None, None


def extract_cvssv4_attr(content):
    """
    example:    CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
                CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P
    return:     AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, E
    """
    m = re.search(
        r"CVSS:4.0\/AV:([NALP])\/AC:([LH])\/AT:([NP])\/PR:([NLH])\/UI:([NPA])\/VC:([HLN])\/VI:([HLN])\/VA:([HLN])\/SC:([HLN])\/SI:([HLN])\/SA:([HLN])\/E:([XAPU])",
        content,
    )
    if m:
        return (
            m.group(1),
            m.group(2),
            m.group(3),
            m.group(4),
            m.group(5),
            m.group(6),
            m.group(7),
            m.group(8),
            m.group(9),
            m.group(10),
            m.group(11),
            m.group(12),
        )
    else:
        m = re.search(
            r"CVSS:4.0\/AV:([NALP])\/AC:([LH])\/AT:([NP])\/PR:([NLH])\/UI:([NPA])\/VC:([HLN])\/VI:([HLN])\/VA:([HLN])\/SC:([HLN])\/SI:([HLN])\/SA:([HLN])",
            content,
        )
        if m:
            return (
                m.group(1),
                m.group(2),
                m.group(3),
                m.group(4),
                m.group(5),
                m.group(6),
                m.group(7),
                m.group(8),
                m.group(9),
                m.group(10),
                m.group(11),
                None
            )
    return None, None, None, None, None, None, None, None, None, None, None, None


def extract_jirakey_num(content):
    """
    example:    INTSI000-1000
    return      1000
    """
    m = re.search(r"INTSI000-(\d{3,4})", content)
    if m:
        return int(m.group(1))
    return None


def extract_sa_title(content):
    """
    example:     INTSI000-732[QPKG][Security][Medium][V3] Exposure of Sensitive Information in CloudLink - CVE-2021-28815 (xxyantixx)
    return:     Exposure of Sensitive Information in CloudLink
    """
    satitle = content
    # print('')
    # print(satitle)
    ### (researcher_name)
    reg_tails = [r"\(.*\)", r"CVE-\d{4}-\d{4,7}"]
    for reg_tail in reg_tails:
        m2 = re.search(reg_tail, satitle)
        if m2:
            idx_tail = satitle.find(m2.group(0))
            satitle = satitle[0:idx_tail]
            # print(satitle)

    reg_heads = [
        r"\[V[12345]\](.*)",
        r"\[Security\](.*)",
        r"\[.*\](.*)",
        r"INTSI\d{3}-\d{4}(.*)",
    ]
    for reg_head in reg_heads:
        m1 = re.search(reg_head, satitle)
        if m1:
            satitle = m1.group(1)
            # print(satitle)

    substrs = ["[Medium]", "[High]", "[Critical]", "[Low]", "[Info]"]
    for substr in substrs:
        satitle = satitle.replace(substr, "")

    satitle = satitle.strip(" -\u00a0")
    return satitle


def extract_pf_pt_ver(content):
    """
    example:    [CVE-2021-28815][FIX]: [QTS 4.5.3] [myQNAPcloud Link] [2.2.21]
    return:     [QTS 4.5.3, myQNAPcloud Link, 2.2.21]
    """
    version_data = []
    idx = content.find("[FIX]:")
    if idx >= 0:
        idx_head = 0
        idx_tail = 0
        pf_pt_ver = content[idx + len("[FIX]:") :]
        while idx_head >= 0 and idx_tail >= 0:
            idx_head = pf_pt_ver.find("[", idx_head)
            idx_tail = pf_pt_ver.find("]", idx_tail)
            if idx_head < 0 or idx_tail < 0:
                break
            item = pf_pt_ver[idx_head + 1 : idx_tail]
            version_data.append(item)
            idx_head += 1
            idx_tail += 1
    return version_data


def sync_summary_content(src, dst):
    """
    src: '[Qmiix Android][Security][Medium][V3] Secret information stored in the application'
    dst: '[Qmiix Android][Security][Medium][V3] Secret information stored in the application'
    """
    ### extract all content enclosed by []
    modified_src = src
    src_keywords = []
    while modified_src.find("[") >= 0:
        m = re.search(r"(\[[^\[\]]*\])", modified_src)
        if m and m.group(1):
            src_keywords.append(m.group(1).lower())
            modified_src = modified_src.replace(m.group(1), "", 1)

    modified_dst = dst
    dst_keywords = []
    while modified_dst.find("[") >= 0:
        m = re.search(r"(\[[^\[\]]*\])", modified_dst)
        if m and m.group(1):
            dst_keywords.append(m.group(1))
            modified_dst = modified_dst.replace(m.group(1), "", 1)

    output = ""
    for keyword in dst_keywords:
        if keyword.lower() in [
            "[security]",
            "[v1]",
            "[v2]",
            "[v3]",
            "[v4]",
            "[v5]",
            "[information]",
            "[low]",
            "[medium]",
            "[high]",
            "[critical]",
        ] and (keyword.lower() not in src_keywords or len(src_keywords) == 0):
            continue
        output += keyword
    if modified_src[0] != " ":
        output += " "
    output += modified_src

    return output


def severity_level_2_cvssv3_score(severity_level):
    severity2cvss = {
        "[V1]": ["0.0", "1.9"],
        "[V2]": ["2.0", "3.9"],
        "[V3]": ["4.0", "6.9"],
        "[V4]": ["7.0", "8.9"],
        "[V5]": ["9.0", "10.0"],
    }
    if severity_level in severity2cvss:
        return severity2cvss[severity_level][0], severity2cvss[severity_level][1]
    return None, None


def qts_version_begin(content):
    ver = "?"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "5" and m.group(2) == "1":
            ver = "5.1.x"
        elif m.group(1) == "5" and m.group(2) == "0":
            ver = "5.0.x"
        elif m.group(1) == "4" and m.group(2) == "5":
            ver = "4.5.x"
        elif m.group(1) == "4" and m.group(2) == "3":
            ver = "4.3.x"
        elif m.group(1) == "4" and m.group(2) == "2":
            ver = "4.2.x"
    return ver


def hero_version_begin(content):
    ver = "?"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "5" and m.group(2) == "2":
            ver = "h5.2.x"
        elif m.group(1) == "5" and m.group(2) == "1":
            ver = "h5.1.x"
        elif m.group(1) == "5" and m.group(2) == "0":
            ver = "h5.0.x"
        elif m.group(1) == "4" and m.group(2) == "5":
            ver = "h4.5.x"
    return ver


def cld_version_begin(content):
    ver = "c5.0.x"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "5":
            ver = "c5.x.x"
        elif m.group(1) == "4" and m.group(2) == "5":
            ver = "c4.5.x"
    return ver


def qvp_version_begin(content):
    ver = "?"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "2":
            ver = "2.0.0"
    return ver


def qvr_version_begin(content):
    ver = "?"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "5" and m.group(2) == "1":
            ver = "5.1.0"
    return ver


def qne_version_begin(content):
    return "1.0.0"


def qes_version_begin(content):
    ver = "?"
    m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})", content)
    if m and m.group(1) and m.group(2) and m.group(3):
        if m.group(1) == "2" and m.group(2) == "2":
            ver = "2.2.0"
    return ver


def cloudweb_version_begin(content):
    return "n/a"


def qnapwebsite_version_begin(content):
    return "n/a"


def ieiwebsite_version_begin(content):
    return "n/a"


def wuwanwebsite_version_begin(content):
    return "n/a"


def qumiro_version_begin(content):
    return "n/a"


def parse_fw_delivery_process(key, model, ver_n_bld, filelink=""):
    """
    key:       [issue] QSSM2116-341, HEROMANP-1590
    model:     [Applied Model] QSW-M2116P-2T2S, QuTScloud
    ver_n_bld: [Build Number] v1.0.6_S210713_26146, QTS 5.0.0.1716 build 20210701
    return:     QSW-M2116P-2T2S, , 1.0.6 build 210713
                QuTScloud, , c4.5.6.1751
    """
    if ver_n_bld == None:
        return "", "", "", ""
    if key and "QSSM2116" in key:
        m = re.search(r"v(\d{1,2}).(\d{1}).(\d{1})_S(\d{6})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " build "
                + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QTS00000" in key:
        m = re.search(
            r"(QTS )?(\d{1,2}\.\d{1}\.\d{1})\.(\d{4}) (build |#)(\d{8})", ver_n_bld
        )
        if m and m.group(2) and m.group(3) and m.group(5):
            product = "QTS"
            platform = ""
            version = m.group(2) + "." + m.group(3) + " build " + m.group(5)
            version_begin = qts_version_begin(m.group(2))
            return product, platform, version, version_begin
        else:
            m = re.search(
                r"(QTS )?(\d{1,2}\.\d{1}\.\d{1}) (build |#)(\d{8})", ver_n_bld
            )
            if m and m.group(2) and m.group(4):
                product = "QTS"
                platform = ""
                version = m.group(2) + " build " + m.group(4)
                version_begin = qts_version_begin(m.group(2))
                return product, platform, version, version_begin
            else:
                m = re.search(r"(QTS )?(\d{1,2}.\d{1}.\d{1})\.(\d{4})", ver_n_bld)
                if m and m.group(2) and m.group(3):
                    product = "QTS"
                    platform = ""
                    version = m.group(2) + "." + m.group(3)
                    version_begin = qts_version_begin(m.group(2))
                    return product, platform, version, version_begin
    elif key and "CLDVCLD0" in key:
        m = re.search(r"(c\d{1,2}.\d{1}.\d{1}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2):
            product = model
            platform = ""
            version = m.group(1) + "." + m.group(2)
            version_begin = cld_version_begin(m.group(1))
            return product, platform, version, version_begin
    elif key and "HEROMANP" in key:
        m = re.search(r"(\d{8})-(h\d{1,2}.\d{1}.\d{1}).(\d{4})(.img)?", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            product = "QuTS hero"
            platform = ""
            version = m.group(2) + "." + m.group(3) + " build " + m.group(1)
            version_begin = hero_version_begin(m.group(2))
            return product, platform, version, version_begin
        else:
            m = re.search(
                r"QuTS hero h(\d{1,2})\.(\d{1})\.(\d{1,2})\.(\d{4}) build (\d{8})?",
                ver_n_bld,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
            ):
                product = "QuTS hero"
                platform = ""
                version = (
                    "h"
                    + m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + "."
                    + m.group(4)
                    + " build "
                    + m.group(5)
                )
                version_begin = hero_version_begin(
                    m.group(1) + "." + m.group(2) + "." + m.group(3)
                )
                return product, platform, version, version_begin
            else:
                m = re.search(r"(\d{4})", ver_n_bld)
                if m and m.group(1):
                    product = "QuTS hero"
                    platform = ""
                    version = m.group(1)
                    version_begin = "0000"
                    return product, platform, version, version_begin
    elif key and "QVPMANPJ" in key:
        m = re.search(r"(\d{1,2})\.(\d{1})\.(\d{1})\.(\d{1})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = "QVR Pro Appliance"
            platform = model
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = qvp_version_begin(
                m.group(1) + "." + m.group(2) + "." + m.group(3)
            )
            return product, platform, version, version_begin
        else:
            m = re.search(
                r"daily_build\\QVP_(\d{1,2})\.(\d{1})\.(\d{1})\\(\d{1,4})", filelink
            )
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
                product = "QVR Pro Appliance"
                platform = model
                version = (
                    m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
                )
                version_begin = qvp_version_begin(
                    m.group(1) + "." + m.group(2) + "." + m.group(3)
                )
                return product, platform, version, version_begin
            else:
                m = re.search(
                    r"QVP-XXB_(\d{8})-(\d{1,2})\.(\d{1})\.(\d{1})\.(\d{1,4}).img",
                    filelink,
                )
                if (
                    m
                    and m.group(1)
                    and m.group(2)
                    and m.group(3)
                    and m.group(4)
                    and m.group(5)
                ):
                    product = "QVR Pro Appliance"
                    platform = model
                    version = (
                        m.group(2)
                        + "."
                        + m.group(3)
                        + "."
                        + m.group(4)
                        + "."
                        + m.group(5)
                        + " build "
                        + m.group(1)
                    )
                    version_begin = m.group(2) + "." + m.group(3) + ".x"
                    return product, platform, version, version_begin

    elif key and "QESMANPJ" in key:
        product = "QES"
        platform = model
        m = re.search(
            r"ES-DUAL_(\d{8})-(\d{1,2})\.(\d{1})\.(\d{1,2})\.\d{4}", ver_n_bld
        )
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            version = (
                m.group(2)
                + "."
                + m.group(3)
                + "."
                + m.group(4)
                + " build "
                + m.group(1)
            )
            version_begin = qes_version_begin(
                m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            return product, platform, version, version_begin
    elif key and "QNEMANPJ" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).q(\d{3})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = "QNE"
            platform = ""
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + ".q" + m.group(4)
            )
            version_begin = qne_version_begin(
                m.group(1) + "." + m.group(2) + "." + m.group(3)
            )
            return product, platform, version, version_begin
        else:
            product = "ADRA Global"
            platform = ""
            version = "QGD-160XP"
            version_begin = "QGD-160x"
            return product, platform, version, version_begin
    elif key and "NVRQVRSV" in key:
        m = re.search(
            r"(\d{1,2})\.(\d{1})\.(\d{1}) \((\d{4})/(\d{2})/(\d{2})\)", ver_n_bld
        )
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4)
            and m.group(5)
            and m.group(6)
        ):
            product = "QVR"
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " build "
                + m.group(4)
                + m.group(5)
                + m.group(6)
            )
            version_begin = qvr_version_begin(
                m.group(1) + "." + m.group(2) + "." + m.group(3)
            )
            return product, platform, version, version_begin
        else:
            m = re.search(r"_(\d{8})-(\d{1,2})\.(\d{1})\.(\d{1,2}).img", filelink)
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
                product = "QVR"
                platform = ""
                version = (
                    m.group(2)
                    + "."
                    + m.group(3)
                    + "."
                    + m.group(4)
                    + " build "
                    + m.group(1)
                )
                version_begin = qvr_version_begin(
                    m.group(2) + "." + m.group(3) + "." + m.group(4)
                )
                return product, platform, version, version_begin
    elif key and "ODMODMMP" in key:
        m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{4})#(\d{8})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4) and m.group(5):
            product = "QTS"
            platform = "Generic"
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + "."
                + m.group(4)
                + " build "
                + m.group(5)
            )
            version_begin = m.group(1) + "." + m.group(2) + "." + m.group(3)
            return product, platform, version, version_begin

    print("---     FW Delivery Process - project {key} not found".format(key=key))
    print("        model = {model}".format(model=str(model)))
    print("        ver_n_bld = {ver_n_bld}".format(ver_n_bld=str(ver_n_bld)))
    print("        filelink = {filelink}".format(filelink=str(filelink)))
    return "", "", "", ""


def parse_fw_release_process(key, summary, content):
    """
    key:        QTS00000-9225
                NVRQVRSV-281
    summary:    QTS 5.0 Beta Release Test for Beta Models-Round 2
                Release Test - QVR FW 5.1.5 build 20210803 (Round 1)
    content:    4.3.3.1693 #20210624
                QTS 4.3.6.1750 build 20210730
                QTS 4.5.4.1715 build 20210630
                QTS 5.0.0.1716 build 20210701
    return      QTS, 4.5.4.1741 build 20210726
    """
    if content == None:
        return "", "", "", ""
    if key and "NVRQVRSV" in key:
        m = re.search(r"(QVR)[ ]FW[ ](\d{1,2}).(\d{1}).(\d{1})", summary)
        if m and m.group(2) and m.group(3) and m.group(4) and m.group(4):
            return (
                "QVR",
                "",
                m.group(2) + "." + m.group(3) + "." + m.group(4) + " build " + content,
                m.group(2) + ".x.x",
            )
    print("---     FW Release Process - project {key} not found".format(key=key))
    return "", "", "", ""


def parse_store_publish_process(
    key, model, platform, ver_n_bld, filelink="", summary=""
):
    """
    key: [issuekey] NVRVRLIT-1922
    model: [Display name] name:QVR
    platform: [Additional note for FW/Platform] for hero h4.5.4
    ver_n_build: [Build Number] 2.1.4.0
    filelink: [File link] \\\\172.17.23.188\\QNAP_Software\\Firmware\2021\\Dec\06\\ubuntu1804\\QELT_B20210412_210_V2140\\QVREliteServer_2.1.4.0_20211206_x86_64.qpkg
    """
    if key and "NVRQUSC2" in key:
        m = re.search(r"(\d{1,2}).(\d{1}).(\d{1,2})_(\d{4})(\d{2})(\d{2})", ver_n_bld)
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4)
            and m.group(5)
            and m.group(6)
        ):
            product = model
            platform = platform
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " ( "
                + m.group(4)
                + "/"
                + m.group(5)
                + "/"
                + m.group(6)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
        else:
            m = re.search(
                r"qusbcam2_(\d{1,2}).(\d{1}).(\d{1,2})_(\d{4})(\d{2})(\d{2})_x86_64",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
                and m.group(6)
            ):
                product = "QUSBCam2"
                platform = ""
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = ver_n_bld
                return product, platform, version, version_begin

    elif key and "KIBKCAAN" in key:
        m = re.search(
            r"(\d{1,2}).(\d{1}).(\d{1,2}) build (\d{4})(\d{2})(\d{2})", ver_n_bld
        )
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4)
            and m.group(5)
            and m.group(6)
        ):
            product = model
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " build "
                + m.group(4)
                + m.group(5)
                + m.group(6)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QSSNSGD0" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = "QGD-1600P"
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QSS1602C" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = "QGD-1600P"
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QSS3012C" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = "QGD-1600P"
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    if key and "QTSMQC00" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2})_(\d{4})(\d{2})(\d{2})", ver_n_bld)
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4) + m.group(5) + m.group(6)
        ):
            product = model
            if platform:
                platform = platform.rstrip()
            else:
                platform = "QTS"
            if len(platform) == 0:
                platform = "QTS"
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " ( "
                + m.group(4)
                + "/"
                + m.group(5)
                + "/"
                + m.group(6)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
        else:
            m = re.search(
                r"MyCloudNas_(\d{1,2}\.\d{1,2})\.\d{1,4}_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
                product = model
                platform = ""
                version = (
                    ver_n_bld
                    + " ( "
                    + m.group(2)
                    + "/"
                    + m.group(3)
                    + "/"
                    + m.group(4)
                    + " )"
                )
                version_begin = m.group(1) + ".x"
                return product, "", version, version_begin
            else:
                m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
                if (
                    m
                    and m.group(1)
                    and m.group(2)
                    and m.group(3)
                ):
                    product = model
                    version = ver_n_bld
                    version_begin = m.group(1) + '.' + m.group(2) + ".x"
                return product, "", version, version_begin

    elif key and "QTSHBS00" in key:
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            product = "Hybrid Backup Sync"
            platform = ""
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
        else:
            m = re.search(r"Hybrid_Backup_Sync_(\d{1})/2", ver_n_bld)
            if m and m.group(1):
                product = "Hybrid Backup Sync"
                platform = ""
                version = m.group(1) + ".0"
                version_begin = m.group(1) + ".x"
                return product, platform, version, version_begin
    elif key and "QTSPTST0" in key:
        if filelink:
            m = re.search(
                r"PhotoStation_(\d{1,2}).(\d{1,2}).(\d{1,2})_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4) + m.group(5) + m.group(6)
            ):
                product = model
                platform = ""
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, platform, version, version_begin
        else:
            buildnum = ""
            m = re.search(r"(\d{4})(\d{2})(\d{2})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                buildnum = (
                    " ( " + m.group(1) + "/" + m.group(2) + "/" + m.group(3) + " )"
                )
            m = re.search(r"Photo Station (\d{1,2}).(\d{1,2}).(\d{1,2})", summary)
            if m and m.group(1) and m.group(2) and m.group(3):
                product = model
                platform = ""
                version = m.group(1) + "." + m.group(2) + "." + m.group(3) + buildnum
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, platform, version, version_begin
    elif key and "NVRSTGEP" in key:
        m = re.search(
            r"\\(\d{1,2}).(\d{1,2}).(\d{1,2})_Build_(\d{4})(\d{2})(\d{2})", filelink
        )
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4) + m.group(5) + m.group(6)
        ):
            product = model
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " ( "
                + m.group(4)
                + "/"
                + m.group(5)
                + "/"
                + m.group(6)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
        if not ver_n_bld:
            return model, "", "1.0.5", "1.0.x"
    elif key and "QTSIMTP0" in key:
        m = re.search(r"v(\d{1,2}).(\d{1,2}).(\d{1,2})-(\d{4})(\d{2})(\d{2})", filelink)
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4) + m.group(5) + m.group(6)
        ):
            product = model
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " ( "
                + m.group(4)
                + "/"
                + m.group(5)
                + "/"
                + m.group(6)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QTSMSAO0" in key:
        product = model
        platform = platform
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,3}).(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if filelink:
            m = re.search(r"_(\d{4})(\d{2})(\d{2}).qpkg", filelink)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = (
                    ver_n_bld
                    + " ( "
                    + m.group(1)
                    + "/"
                    + m.group(2)
                    + "/"
                    + m.group(3)
                    + " )"
                )
            return product, platform, version, version_begin
    elif key and "AFOTKAND" in key:
        product = model.strip()
        if platform:
            m = re.search(r"KoiTalk (.*) \d{1,2}.\d{1,2}.\d{1,2}", platform)
            if m and m.group(1):
                platform = m.group(1)
            else:
                platform = ""
        else:
            platform = ""

        m = re.search(r"/KoiTalk(\d{1,2}).(\d{1,2}).(\d{1,2}).\d{1,2}-prod", filelink)
        if m and m.group(1) and m.group(2) and m.group(3):
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
        else:
            m = re.search(r"v(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, platform, version, version_begin
    elif key and "CMNMINIS" in key:
        product = model.strip()
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1}).(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        return product, "", version, version_begin
    elif key and "QTSMTMC0" in key:
        product = model
        platform = ""
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1}).(\d{1})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if filelink:
            m = re.search(r"\\MultimediaConsole\\(\d{4})\\(\d{2})\\(\d{2})", filelink)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = (
                    ver_n_bld
                    + " ( "
                    + m.group(1)
                    + "/"
                    + m.group(2)
                    + "/"
                    + m.group(3)
                    + " )"
                )
        return product, platform, version, version_begin
    elif key and "NVRSVLST" in key:
        product = model
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1}).(\d{1}).(\d{1}).(\d{1})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4) and m.group(5):
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + "."
                + m.group(4)
                + "."
                + m.group(5)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if filelink:
            m = re.search(
                r"SurveillanceStation_\d{1}.\d{1}.\d{1}.\d{1}.\d{1}_(\d{4})(\d{2})(\d{2})_",
                filelink,
            )
            if m and m.group(1) and m.group(2) and m.group(3):
                version = (
                    ver_n_bld
                    + " ( "
                    + m.group(1)
                    + "/"
                    + m.group(2)
                    + "/"
                    + m.group(3)
                    + " )"
                )
        return product, platform, version, version_begin
    elif key and "QTSMAG00" in key:
        product = model
        version = ver_n_bld
        if platform:
            m = re.search(r"FW (\d{1}).(\d{1}).\d{1}", platform)
            if m and m.group(1) and m.group(2):
                platform = "QTS " + m.group(1) + "." + m.group(2)
            else:
                m = re.search(r"FW h(\d{1}).(\d{1}).(\d{1})", platform)
                if m and m.group(1) and m.group(2) and m.group(3):
                    platform = (
                        "QuTS hero h" + m.group(1) + "." + m.group(2) + "." + m.group(3)
                    )
        if filelink:
            m = re.search(
                r"Qmail/DailyBuild_Qmail/(\d{1,2}).(\d{1,2}).(\d{1,2})/(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
                and m.group(6)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
        return product, platform, version, version_begin
    elif key and "ANDCTZ00" in key:
        product = model
        version = ver_n_bld
        if model == "AND Qcontactz":
            product = "Qcontactz"
        if filelink:
            m = re.search(
                r"/Qcontactz-(\d{1}).(\d{1}).(\d{1}).(\d{1}).(\d{8})-", filelink
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + "."
                    + m.group(4)
                    + "."
                    + m.group(5)
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
        return product, "", version, version_begin
    elif key and "CMNLINKS" in key:
        product = model
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if model == "KazooServer":
            product = "Kazoo Server"
        return product, "", version, version_begin
    elif key and "ANDFLAD0" in key:
        product = model
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if model:
            m = re.search(r"(Qfile) Android \d{1}.\d{1}.\d{1}", model)
            if m and m.group(1):
                product = m.group(1)
        return product, "", version, version_begin
    elif key and ("NVRVRLIT" in key or "QVRPRGRD" in key):
        product = model
        if platform:
            m = re.search(r"[Ff]or (QTS |hero )h?(\d{1}).(\d{1}).?(\d{1})?", platform)
            if m and m.group(1) and m.group(1) == "hero " and m.group(2) and m.group(3):
                platform = "QuTS hero h" + m.group(2) + "." + m.group(3)
            elif (
                m and m.group(1) and m.group(1) == "QTS " and m.group(2) and m.group(3)
            ):
                platform = "QTS " + m.group(2) + "." + m.group(3)
            else:
                platform = "QTS "
            if m and m.group(4) and len(m.group(4)) > 0:
                platform += "." + m.group(4)
            else:
                platform += ".0"
        version = ver_n_bld
        version_begin = ver_n_bld
        m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
        if filelink:
            m = re.search(
                r"QVREliteServer_\d{1}.\d{1}.\d{1}.\d{1}_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if m and m.group(1) and m.group(2) and m.group(3):
                version += " (" + m.group(1) + "/" + m.group(2) + "/" + m.group(3) + ")"
            else:
                m = re.search(
                    r"QVRProServer_\d{1}.\d{1}.\d{1}.\d{1}_(\d{4})(\d{2})(\d{2})",
                    filelink,
                )
                if m and m.group(1) and m.group(2) and m.group(3):
                    version += (
                        " (" + m.group(1) + "/" + m.group(2) + "/" + m.group(3) + ")"
                    )
                else:
                    m = re.search(
                        r"QVRGuard_\d{1}.\d{1}.\d{1}.\d{1}_(\d{4})(\d{2})(\d{2})",
                        filelink,
                    )
                    if m and m.group(1) and m.group(2) and m.group(3):
                        version += (
                            " ("
                            + m.group(1)
                            + "/"
                            + m.group(2)
                            + "/"
                            + m.group(3)
                            + ")"
                        )
        return product, platform, version, version_begin
    elif key and "QTSQKLAG" in key:
        product = model
        if ver_n_bld:
            m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "QTSPXSV0" in key:
        product = model
        if not platform:
            platform = ""
        else:
            m = re.search(r"h(\d{1,2}).(\d{1,2}).(\d{1,2})", platform)
            if m and m.group(1) and m.group(2) and m.group(3):
                platform = (
                    "QuTS hero h" + m.group(1) + "." + m.group(2) + "." + m.group(3)
                )
        version = ""
        if filelink:
            m = re.search(
                r"ProxyServer_(\d{1,2}).(\d{1,2}).(\d{1,2})_(x86_64|arm_64)_(\d{4})(\d{2})(\d{2})\d{6}.qpkg",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(5)
                and m.group(6)
                and m.group(7)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + "/"
                    + m.group(7)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, platform, version, version_begin
    elif key and "ANDSCAP0" in key:
        product = model
        platform = ""
        version = ""
        if filelink:
            m = re.search(
                r"/job/\((Android)\)%20Qsirch_v\d{1,2}.\d{1,2}.\d{1,2}/", filelink
            )
            if m and m.group(1):
                platform = m.group(1)
        if ver_n_bld:
            m = re.search(
                r"Qsirch-(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{1,2}).5efbc49-(\d{8})",
                ver_n_bld,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + "."
                    + m.group(4)
                    + "."
                    + m.group(5)
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
        return product, platform, version, version_begin
    elif key and "CLDVCLD0" in key:
        m = re.search(r"(\d{1,2}).(\d{1}).(\d{1}).(\d{1})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = ""
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QTSVDOST" in key:
        product = model
        version = ver_n_bld
        if filelink:
            m = re.search(
                r"VideoStationPro_(\d{1,2}).(\d{1,2}).(\d{1,2})_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4) + m.group(5) + "." + m.group(6)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
        else:
            buildnum = ""
            m = re.search(r"(\d{4})(\d{2})(\d{2})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                buildnum = (
                    " ( " + m.group(1) + "/" + m.group(2) + "/" + m.group(3) + " )"
                )

            m = re.search(r"VideoStation v(\d{1,2})\.(\d{1,2})\.(\d{1,2})", summary)
            if m and m.group(1) and m.group(2) and m.group(3):
                product = model
                platform = ""
                version = m.group(1) + "." + m.group(2) + "." + m.group(3) + buildnum
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, platform, version, version_begin
    elif key and "QTSDLST0" in key:
        product = model
        version = ver_n_bld
        if filelink:
            m = re.search(
                r"DownloadStation_(\d{1,2}).(\d{1,2}).(\d{1,2}).(\d{3})_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4) + m.group(5) + "." + m.group(6) + "." + m.group(7)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + "."
                    + m.group(4)
                    + " ( "
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + "/"
                    + m.group(7)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "QTSVPNSV" in key:
        product = model
        if ver_n_bld:
            m = re.search(r"QVPN (\d{1,2}).(\d{1,2}).(\d{1,3})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "VAPROONS" in key:
        product = model
        if ver_n_bld:
            m = re.search(r"(\d{4})-(\d{2})-(\d{2})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "-" + m.group(2) + "-" + m.group(3)
                version_begin = m.group(1) + "-xx-xx"
                return product, "", version, version_begin
    elif key and "ANDQMGAD" in key:
        product = model
        if model:
            m = re.search(r"(QuMagie).*", model)
            if m and m.group(1):
                product = m.group(1)
        if ver_n_bld:
            m = re.search(
                r"(\d{1,2}).(\d{1,2}).(\d{1,2}).\d{1,2}.\d{4}\d{2}\d{2}", ver_n_bld
            )
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + ".x.x"
                return product, "", version, version_begin
            elif filelink:
                m = re.search(
                    r"QNAPQuMagieAndroid-(\d{1,2}\.\d{1,2})\.(\d{1,2})\.(\d{1,4})",
                    filelink,
                )
                if m and m.group(1) and m.group(2) and m.group(3):
                    product = model
                    platform = ""
                    version = (
                        m.group(1)
                        + "."
                        + m.group(2)
                        + "."
                        + m.group(3)
                    )
                    version_begin = m.group(1) + ".x"
                    return product, "", version, version_begin


    elif key and "QWSMAND0" in key:
        product = model
        if model:
            m = re.search(r"(QuRouter).*", model)
            if m and m.group(1):
                product = m.group(1)
        if ver_n_bld:
            m = re.search(r"(\d{1,2}).(\d{1,2}).(\d{1,2}).\d{4}", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + ".x.x"
                return product, "", version, version_begin
    elif key and "QTS00000" in key:
        if filelink and filelink.find("Cinema28") >= 0:
            m = re.search(
                r"Cinema28_(\d{1,2})\.(\d{1,2})\.(\d{1,2})_(\d{4})(\d{2})(\d{2})_",
                filelink,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4) + m.group(5) + m.group(6)
            ):
                product = "Cinema28"
                platform = ""
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "QTSQMAGI" in key:
        product = "QuMagie"
        if ver_n_bld:
            m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,3})", ver_n_bld)
            if m and m.group(1) and m.group(2) and m.group(3):
                version = m.group(1) + "." + m.group(2) + "." + m.group(3)
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "KIBKMIOS" in key:
        product = model
        if ver_n_bld:
            m = re.search(
                r"KoiMeeter (\d{1,2})\.(\d{1,2})\.(\d{1,2}) \((\d{4})(\d{2})(\d{2})\d{4}\)",
                ver_n_bld,
            )
            if (
                m
                and m.group(1)
                and m.group(2)
                and m.group(3)
                and m.group(4)
                and m.group(5)
                and m.group(6)
            ):
                version = (
                    m.group(1)
                    + "."
                    + m.group(2)
                    + "."
                    + m.group(3)
                    + " ( "
                    + m.group(4)
                    + "/"
                    + m.group(5)
                    + "/"
                    + m.group(6)
                    + " )"
                )
                version_begin = m.group(1) + "." + m.group(2) + ".x"
                return product, "", version, version_begin
    elif key and "QTSVPNWS" in key:
        m = re.search(
            r"QNAPQVPNWindows-(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{4})", filelink
        )
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = ""
            version = (
                m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4)
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, "", version, version_begin
    elif key and "QTSQULCT" in key:
        m = re.search(
            r"QuLog_(\d{1,2}\.\d{1,2})\.\d{1,2}\.\d{3,4}_(\d{4})(\d{2})(\d{2})",
            filelink,
        )
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = ""
            version = (
                ver_n_bld
                + " ( "
                + m.group(2)
                + "/"
                + m.group(3)
                + "/"
                + m.group(4)
                + " )"
            )
            version_begin = m.group(1) + ".x.x"
            return product, "", version, version_begin
    elif key and "CMNQUFRW" in key:
        m = re.search(
            r"qufirewall\\release_v(\d{1,2})\.(\d{1,2})\.(\d{1,2})\\(\d{4})(\d{2})(\d{2})\\",
            filelink,
        )
        if (
            m
            and m.group(1)
            and m.group(2)
            and m.group(3)
            and m.group(4) + m.group(5) + m.group(6)
        ):
            product = "QuFirewall"
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + " ( "
                + m.group(4)
                + "/"
                + m.group(5)
                + "/"
                + m.group(6)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, "", version, version_begin
        else:    
            m = re.search(
                r"qufirewall_(\d{1,2}\.\d{1,2})\.\d{1,2}_(\d{4})(\d{2})(\d{2})",
                filelink,
            )
            if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
                product = model
                platform = ""
                version = (
                    ver_n_bld
                    + " ( "
                    + m.group(2)
                    + "/"
                    + m.group(3)
                    + "/"
                    + m.group(4)
                    + " )"
                )
                version_begin = m.group(1) + ".x"
                return product, "", version, version_begin
    elif key and "QVRPOCNT" in key:
        m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{4})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = "QVR Pro Client"
            version = ver_n_bld
            version_begin = m.group(1) + "." + m.group(2) + ".x.x"
            return product, platform, version, version_begin
    elif key and "QTSMS000" in key:
        m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3):
            product = "Music Station"
            platform = ""
            version = m.group(1) + "." + m.group(2) + "." + m.group(3)
            version_begin = m.group(1) + "." + m.group(2) + ".x"
            return product, platform, version, version_begin
    elif key and "QTSCTST0" in key:
        m = re.search(r"(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})", ver_n_bld)
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = "Container Station"
            platform = ""
            version = ver_n_bld
            version_begin = m.group(1) + "." + m.group(2) + ".x.x"
            return product, platform, version, version_begin
    elif key and "ANDQNOTE" in key:
        m = re.search(
            r"Qnotes3-(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{8})", filelink
        )
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4) and m.group(5):
            product = "Qnotes3"
            platform = ""
            version = (
                m.group(1)
                + "."
                + m.group(2)
                + "."
                + m.group(3)
                + "."
                + m.group(4)
                + " build ( "
                + m.group(5)
                + " )"
            )
            version_begin = m.group(1) + "." + m.group(2) + ".x.x"
            return product, platform, version, version_begin
    elif key and "VAPQSYCT" in key:
        m = re.search(
            r"QsyncServer_(\d{1,2}\.\d{1,2})\.\d{1,2}\.\d{1,4}_(\d{4})(\d{2})(\d{2})",
            filelink,
        )
        if m and m.group(1) and m.group(2) and m.group(3) and m.group(4):
            product = model
            platform = ""
            version = (
                ver_n_bld
                + " ( "
                + m.group(2)
                + "/"
                + m.group(3)
                + "/"
                + m.group(4)
                + " )"
            )
            version_begin = m.group(1) + ".x.x"
            return product, "", version, version_begin
    elif key and "QTSNTSTN" in key:
        m = re.search(
            r"(\d{1,2}\.\d{1,2})\.(\d{1,2})-\d{4}\d{2}\d{2}",
            ver_n_bld,
        )
        if m and m.group(1) and m.group(2):
            product = model
            platform = ""
            version = m.group(1) + "." + m.group(2)
            version_begin = m.group(1) + ".x"
            return product, "", version, version_begin

    print("---     Store Publish Process - project {key} not found".format(key=key))
    print("        model = {model}".format(model=str(model)))
    print("        platform = {platform}".format(platform=str(platform)))
    print("        ver_n_bld = {ver_n_bld}".format(ver_n_bld=str(ver_n_bld)))
    print("        filelink = {filelink}".format(filelink=str(filelink)))
    print("        summary = {summary}".format(summary=str(summary)))
    return "", "", "", ""


def parse_app_release_process(key, product, platform, version):
    """
    key:        NVRQUSC2-207
    product:    QUSBCam2
    platform:   QuTS hero 4.5.3
    version:    1.1.4_20210730
                2.0.1_20210803 & 2.0.1_20210804
    return      QUSBCam2, QuTS hero 4.5.3, 1.1.4 ( 2021/08/04 )
    """
    print("---     App Release Process - project {key} not found".format(key=key))
    return "", "", ""
