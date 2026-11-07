# Base-score calculator for CVSS v4.0 vectors (base metrics only).
#
# Algorithm and lookup tables are a condensed port of the CVSS v4.0 reference
# implementation in the `cvss` Python package (3.6), itself a port of
# https://github.com/RedHatProductSecurity/cvss-v4-calculator.
# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE.
#
# Threat / environmental / supplemental metrics are deliberately unsupported:
# the pipeline scores the vulnerability as found (CVSS-B), and business context
# is a separate, explicit step in hermes_review.py.
"""CVSS v4.0 base score and severity. Stdlib only.

    score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") -> 10.0
    severity(10.0) -> "Critical"
Raises ValueError on a vector that is not exactly the 11 base metrics.
"""

from decimal import ROUND_HALF_UP, Decimal

MAX_COMPOSED = {'eq1': {'0': ['AV:N/PR:N/UI:N/'],
         '1': ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
         '2': ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']},
 'eq2': {'0': ['AC:L/AT:N/'], '1': ['AC:H/AT:N/', 'AC:L/AT:P/']},
 'eq3': {'0': {'0': ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
               '1': ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']},
         '1': {'0': ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
               '1': ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
                     'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
                     'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']},
         '2': {'1': ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']}},
 'eq4': {'0': ['SC:H/SI:S/SA:S/'], '1': ['SC:H/SI:H/SA:H/'], '2': ['SC:L/SI:L/SA:L/']},
 'eq5': {'0': ['E:A/'], '1': ['E:P/'], '2': ['E:U/']}}

MAX_SEVERITY = {'eq1': {0: 1, 1: 4, 2: 5},
 'eq2': {0: 1, 1: 2},
 'eq3eq6': {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
 'eq4': {0: 6, 1: 5, 2: 4},
 'eq5': {0: 1, 1: 1, 2: 1}}

LOOKUP = {'000000': 10.0,
 '000001': 9.9,
 '000010': 9.8,
 '000011': 9.5,
 '000020': 9.5,
 '000021': 9.2,
 '000100': 10.0,
 '000101': 9.6,
 '000110': 9.3,
 '000111': 8.7,
 '000120': 9.1,
 '000121': 8.1,
 '000200': 9.3,
 '000201': 9.0,
 '000210': 8.9,
 '000211': 8.0,
 '000220': 8.1,
 '000221': 6.8,
 '001000': 9.8,
 '001001': 9.5,
 '001010': 9.5,
 '001011': 9.2,
 '001020': 9.0,
 '001021': 8.4,
 '001100': 9.3,
 '001101': 9.2,
 '001110': 8.9,
 '001111': 8.1,
 '001120': 8.1,
 '001121': 6.5,
 '001200': 8.8,
 '001201': 8.0,
 '001210': 7.8,
 '001211': 7.0,
 '001220': 6.9,
 '001221': 4.8,
 '002001': 9.2,
 '002011': 8.2,
 '002021': 7.2,
 '002101': 7.9,
 '002111': 6.9,
 '002121': 5.0,
 '002201': 6.9,
 '002211': 5.5,
 '002221': 2.7,
 '010000': 9.9,
 '010001': 9.7,
 '010010': 9.5,
 '010011': 9.2,
 '010020': 9.2,
 '010021': 8.5,
 '010100': 9.5,
 '010101': 9.1,
 '010110': 9.0,
 '010111': 8.3,
 '010120': 8.4,
 '010121': 7.1,
 '010200': 9.2,
 '010201': 8.1,
 '010210': 8.2,
 '010211': 7.1,
 '010220': 7.2,
 '010221': 5.3,
 '011000': 9.5,
 '011001': 9.3,
 '011010': 9.2,
 '011011': 8.5,
 '011020': 8.5,
 '011021': 7.3,
 '011100': 9.2,
 '011101': 8.2,
 '011110': 8.0,
 '011111': 7.2,
 '011120': 7.0,
 '011121': 5.9,
 '011200': 8.4,
 '011201': 7.0,
 '011210': 7.1,
 '011211': 5.2,
 '011220': 5.0,
 '011221': 3.0,
 '012001': 8.6,
 '012011': 7.5,
 '012021': 5.2,
 '012101': 7.1,
 '012111': 5.2,
 '012121': 2.9,
 '012201': 6.3,
 '012211': 2.9,
 '012221': 1.7,
 '100000': 9.8,
 '100001': 9.5,
 '100010': 9.4,
 '100011': 8.7,
 '100020': 9.1,
 '100021': 8.1,
 '100100': 9.4,
 '100101': 8.9,
 '100110': 8.6,
 '100111': 7.4,
 '100120': 7.7,
 '100121': 6.4,
 '100200': 8.7,
 '100201': 7.5,
 '100210': 7.4,
 '100211': 6.3,
 '100220': 6.3,
 '100221': 4.9,
 '101000': 9.4,
 '101001': 8.9,
 '101010': 8.8,
 '101011': 7.7,
 '101020': 7.6,
 '101021': 6.7,
 '101100': 8.6,
 '101101': 7.6,
 '101110': 7.4,
 '101111': 5.8,
 '101120': 5.9,
 '101121': 5.0,
 '101200': 7.2,
 '101201': 5.7,
 '101210': 5.7,
 '101211': 5.2,
 '101220': 5.2,
 '101221': 2.5,
 '102001': 8.3,
 '102011': 7.0,
 '102021': 5.4,
 '102101': 6.5,
 '102111': 5.8,
 '102121': 2.6,
 '102201': 5.3,
 '102211': 2.1,
 '102221': 1.3,
 '110000': 9.5,
 '110001': 9.0,
 '110010': 8.8,
 '110011': 7.6,
 '110020': 7.6,
 '110021': 7.0,
 '110100': 9.0,
 '110101': 7.7,
 '110110': 7.5,
 '110111': 6.2,
 '110120': 6.1,
 '110121': 5.3,
 '110200': 7.7,
 '110201': 6.6,
 '110210': 6.8,
 '110211': 5.9,
 '110220': 5.2,
 '110221': 3.0,
 '111000': 8.9,
 '111001': 7.8,
 '111010': 7.6,
 '111011': 6.7,
 '111020': 6.2,
 '111021': 5.8,
 '111100': 7.4,
 '111101': 5.9,
 '111110': 5.7,
 '111111': 5.7,
 '111120': 4.7,
 '111121': 2.3,
 '111200': 6.1,
 '111201': 5.2,
 '111210': 5.7,
 '111211': 2.9,
 '111220': 2.4,
 '111221': 1.6,
 '112001': 7.1,
 '112011': 5.9,
 '112021': 3.0,
 '112101': 5.8,
 '112111': 2.6,
 '112121': 1.5,
 '112201': 2.3,
 '112211': 1.3,
 '112221': 0.6,
 '200000': 9.3,
 '200001': 8.7,
 '200010': 8.6,
 '200011': 7.2,
 '200020': 7.5,
 '200021': 5.8,
 '200100': 8.6,
 '200101': 7.4,
 '200110': 7.4,
 '200111': 6.1,
 '200120': 5.6,
 '200121': 3.4,
 '200200': 7.0,
 '200201': 5.4,
 '200210': 5.2,
 '200211': 4.0,
 '200220': 4.0,
 '200221': 2.2,
 '201000': 8.5,
 '201001': 7.5,
 '201010': 7.4,
 '201011': 5.5,
 '201020': 6.2,
 '201021': 5.1,
 '201100': 7.2,
 '201101': 5.7,
 '201110': 5.5,
 '201111': 4.1,
 '201120': 4.6,
 '201121': 1.9,
 '201200': 5.3,
 '201201': 3.6,
 '201210': 3.4,
 '201211': 1.9,
 '201220': 1.9,
 '201221': 0.8,
 '202001': 6.4,
 '202011': 5.1,
 '202021': 2.0,
 '202101': 4.7,
 '202111': 2.1,
 '202121': 1.1,
 '202201': 2.4,
 '202211': 0.9,
 '202221': 0.4,
 '210000': 8.8,
 '210001': 7.5,
 '210010': 7.3,
 '210011': 5.3,
 '210020': 6.0,
 '210021': 5.0,
 '210100': 7.3,
 '210101': 5.5,
 '210110': 5.9,
 '210111': 4.0,
 '210120': 4.1,
 '210121': 2.0,
 '210200': 5.4,
 '210201': 4.3,
 '210210': 4.5,
 '210211': 2.2,
 '210220': 2.0,
 '210221': 1.1,
 '211000': 7.5,
 '211001': 5.5,
 '211010': 5.8,
 '211011': 4.5,
 '211020': 4.0,
 '211021': 2.1,
 '211100': 6.1,
 '211101': 5.1,
 '211110': 4.8,
 '211111': 1.8,
 '211120': 2.0,
 '211121': 0.9,
 '211200': 4.6,
 '211201': 1.8,
 '211210': 1.7,
 '211211': 0.7,
 '211220': 0.8,
 '211221': 0.2,
 '212001': 5.3,
 '212011': 2.4,
 '212021': 1.4,
 '212101': 2.4,
 '212111': 1.2,
 '212121': 0.5,
 '212201': 1.0,
 '212211': 0.3,
 '212221': 0.1}

VALID = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
}
ORDER = list(VALID)

_AV = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
_PR = {"N": 0.0, "L": 0.1, "H": 0.2}
_UI = {"N": 0.0, "P": 0.1, "A": 0.2}
_AC = {"L": 0.0, "H": 0.1}
_AT = {"N": 0.0, "P": 0.1}
_V = {"H": 0.0, "L": 0.1, "N": 0.2}
_S = {"H": 0.1, "L": 0.2, "N": 0.3}
LEVELS = {"AV": _AV, "PR": _PR, "UI": _UI, "AC": _AC, "AT": _AT,
          "VC": _V, "VI": _V, "VA": _V, "SC": _S, "SI": _S, "SA": _S}
# Threat and environmental metrics are at their defaults: E=A, CR=IR=AR=H.
_REQ = {"CR": 0.0, "IR": 0.0, "AR": 0.0}


def parse(vector: str) -> dict:
    if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/") or vector.endswith("/"):
        raise ValueError("not a CVSS:4.0 vector")
    metrics = {}
    for field in vector.split("/")[1:]:
        key, sep, value = field.partition(":")
        if not sep or key not in VALID or value not in VALID[key] or len(value) != 1 or key in metrics:
            raise ValueError(f"invalid or duplicate metric {field!r}")
        metrics[key] = value
    if set(metrics) != set(VALID):
        raise ValueError("vector must contain exactly the base metrics " + "/".join(ORDER))
    return metrics


def _round(x: float) -> float:
    return float(Decimal(x + 1e-6).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def _macro(m: dict) -> str:
    av, pr, ui = m["AV"], m["PR"], m["UI"]
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if m["AC"] == "L" and m["AT"] == "N" else 1
    if m["VC"] == "H" and m["VI"] == "H":
        eq3 = 0
    elif "H" in (m["VC"], m["VI"], m["VA"]):
        eq3 = 1
    else:
        eq3 = 2
    eq4 = 1 if "H" in (m["SC"], m["SI"], m["SA"]) else 2
    eq6 = 0 if "H" in (m["VC"], m["VI"], m["VA"]) else 1  # CR=IR=AR=H by default
    return f"{eq1}{eq2}{eq3}{eq4}0{eq6}"


def score(vector: str) -> float:
    m = parse(vector)
    if all(m[k] == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    mv = _macro(m)
    value = LOOKUP[mv]
    e1, e2, e3, e4, e5, e6 = (int(c) for c in mv)

    def at(*digits) -> float:
        return LOOKUP.get("".join(str(d) for d in digits), float("nan"))

    s1 = at(e1 + 1, e2, e3, e4, e5, e6)
    s2 = at(e1, e2 + 1, e3, e4, e5, e6)
    if e3 == 1 and e6 == 1 or e3 == 0 and e6 == 1:
        s36 = at(e1, e2, e3 + 1, e4, e5, e6)
    elif e3 == 1 and e6 == 0:
        s36 = at(e1, e2, e3, e4, e5, e6 + 1)
    elif e3 == 0 and e6 == 0:
        s36 = max(at(e1, e2, e3, e4, e5, e6 + 1), at(e1, e2, e3 + 1, e4, e5, e6))
    else:
        s36 = at(e1, e2, e3 + 1, e4, e5, e6 + 1)
    s4 = at(e1, e2, e3, e4 + 1, e5, e6)
    s5 = at(e1, e2, e3, e4, e5 + 1, e6)

    max_vectors = []
    for a in MAX_COMPOSED["eq1"][str(e1)]:
        for b in MAX_COMPOSED["eq2"][str(e2)]:
            for c in MAX_COMPOSED["eq3"][str(e3)][str(e6)]:
                for d in MAX_COMPOSED["eq4"][str(e4)]:
                    for e in MAX_COMPOSED["eq5"][str(e5)]:
                        max_vectors.append(a + b + c + d + e)

    dist = {}
    for mx in max_vectors:
        mxm = dict(p.split(":") for p in mx.rstrip("/").split("/"))
        dist = {k: LEVELS[k][m[k]] - LEVELS[k][mxm[k]] for k in LEVELS}
        dist.update({k: 0.0 for k in _REQ})  # CR/IR/AR: H vs H
        if all(v >= 0 for v in dist.values()):
            break

    cur1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur2 = dist["AC"] + dist["AT"]
    cur36 = dist["VC"] + dist["VI"] + dist["VA"]
    cur4 = dist["SC"] + dist["SI"] + dist["SA"]
    step = 0.1
    parts = []
    for avail, cur, top in (
        (value - s1, cur1, MAX_SEVERITY["eq1"][e1] * step),
        (value - s2, cur2, MAX_SEVERITY["eq2"][e2] * step),
        (value - s36, cur36, MAX_SEVERITY["eq3eq6"][e3][e6] * step),
        (value - s4, cur4, MAX_SEVERITY["eq4"][e4] * step),
    ):
        if avail == avail and avail >= 0:  # not NaN
            parts.append(avail * (cur / top))
    if value - s5 == value - s5 and value - s5 >= 0:
        parts.append(0.0)  # EQ5 contributes no distance (E fixed at A)
    mean = sum(parts) / len(parts) if parts else 0.0
    return _round(min(10.0, max(0.0, value - mean)))


def severity(base_score: float) -> str:
    if base_score >= 9.0:
        return "Critical"
    if base_score >= 7.0:
        return "High"
    if base_score >= 4.0:
        return "Medium"
    if base_score > 0.0:
        return "Low"
    return "None"
