#!/bin/env python3
#
# acme4j - Java ACME client
#
# Copyright (C) 2022 Richard "Shred" Körber
#   http://acme4j.shredzone.org
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

#
# This tool creates ACME test e-mails and signs them. It can be
# used to generate S/MIME mails for unit tests.
#
# Requires: M2Crypto
#
# WARNING: DO NOT USE THIS CODE TO GENERATE REAL S/MIME MAILS!
#   This generator is only meant to create test mails for unit test
#   purposes, and may lack security relevant features that are
#   needed for real S/MIME mails.
#

from M2Crypto import BIO, Rand, SMIME

def makebuf(text):
    return BIO.MemoryBuffer(bytes(text, 'UTF-8'))

def signmail(text, sender, recipient, subject, privkey, pubkey,
             envelopeFrom=None, envelopeTo=None, envelopeSubject=None):
    body = 'Content-Type: message/RFC822; forwarded=no\r\n\r\n'
    body += 'From: {}\r\n'.format(sender)
    body += 'To: {}\r\n'.format(recipient)
    body += 'Subject: {}\r\n'.format(subject)
    body += 'Message-ID: <A2299BB.FF7788@example.org>\r\n'
    body += 'MIME-Version: 1.0\r\n'
    body += 'Content-Type: text/plain; charset=utf-8\r\n'
    body += '\r\n'
    body += text
    body += '\r\n'

    s = SMIME.SMIME()
    s.load_key(privkey, pubkey)
    p7 = s.sign(makebuf(body), SMIME.PKCS7_DETACHED)

    out = BIO.MemoryBuffer()
    out.write('From: {}\r\n'.format(envelopeFrom if envelopeFrom is not None else sender))
    out.write('To: {}\r\n'.format(envelopeTo if envelopeTo is not None else recipient))
    out.write('Subject: {}\r\n'.format(envelopeSubject if envelopeSubject is not None else subject))
    out.write('Auto-Submitted: auto-generated; type=acme\r\n')
    out.write('Message-ID: <A2299BB.FF7788@example.org>\r\n')
    s.write(out, p7, makebuf(body))

    return out.read()

with open('src/test/resources/email/valid-mail.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-privkey.pem',
        'src/test/resources/valid-signer.pem'))

with open('src/test/resources/email/invalid-cert-mismatch.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'different-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-privkey.pem',
        'src/test/resources/valid-signer.pem',
        envelopeFrom="different-ca@example.org"))

with open('src/test/resources/email/invalid-nosan.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-nosan-privkey.pem',
        'src/test/resources/valid-signer-nosan.pem'))

with open('src/test/resources/email/invalid-signed-mail.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/invalid-signer-privkey.pem',
        'src/test/resources/invalid-signer.pem'))

with open('src/test/resources/email/invalid-protected-mail-from.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-privkey.pem',
        'src/test/resources/valid-signer.pem',
        envelopeFrom="tampered-ca@example.org"))

with open('src/test/resources/email/invalid-protected-mail-to.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-privkey.pem',
        'src/test/resources/valid-signer.pem',
        envelopeTo="tampered-recipient@example.com"))

with open('src/test/resources/email/invalid-protected-mail-subject.eml', 'wb') as w:
    w.write(signmail('This is an automatically generated ACME challenge.',
        'valid-ca@example.com',
        'recipient@example.org',
        'ACME: LgYemJLy3F1LDkiJrdIGbEzyFJyOyf6vBdyZ1TG3sME=',
        'src/test/resources/valid-signer-privkey.pem',
        'src/test/resources/valid-signer.pem',
        envelopeSubject="ACME: aDiFfErEnTtOkEn"))
