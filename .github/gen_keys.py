#!/usr/bin/env python
# -*- coding: utf-8 -*-

from toyecc import AffineCurvePoint, getcurvebyname,  FieldElement,ECPrivateKey,ECPublicKey,Tools
from toyecc.Random import secure_rand_int_between



def gen_ec_kcdsa():
    curve = getcurvebyname('Curve25519')
    ECPrivateKey.generate(curve)