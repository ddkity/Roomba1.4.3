#!/usr/bin/env python
# coding: utf8
#***************************************************************************************************

import argparse
import sys, glob, os
import xml.etree.ElementTree as xmltree

#***************************************************************************************************
class dsn(object):
  class AccessDSNFileError(Exception):
    pass

  class InvalidDSNFileFormat(SyntaxError):
    pass

  def __init__(self, **kwargs):
    if 'file' in kwargs:
      self.dsn = None
      self.pubkey = None
      try:
        xml = xmltree.parse (kwargs['file'])
        if xml:
          f_device = xml.getroot ()
          if f_device.tag == 'f-device':
            for child in f_device:
              if child.tag == 'dsn':
                self.dsn = child.text
              elif child.tag == 'public-key':
                self.pubkey = child.text

        if self.dsn is None or self.pubkey is None:
          raise SyntaxError

      except SyntaxError:
        raise dsn.InvalidDSNFileFormat
      except:
        raise dsn.AccessDSNFileError

    elif 'dsn' in kwargs and 'pubkey' in kwargs:
        self.dsn    = kwargs['dsn']
        self.pubkey = kwargs['pubkey']

#***************************************************************************************************
# main
if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('dsn_file', help='DSN file')
  args = parser.parse_args()

  for file in glob.glob (args.dsn_file):
    try:
      info = dsn (file=file)
      BEGIN = '-----BEGIN RSA PUBLIC KEY-----'
      END = '-----END RSA PUBLIC KEY-----'
      pubkey = info.pubkey
      i1 = pubkey.find (BEGIN)
      i2 = pubkey.find (END)
      if i1 >= 0 and i2 > i1:
        pubkey = pubkey[i1+len (BEGIN):i2]
        pubkey = pubkey.replace ('\n', '')

      print
      print 'id mfg_model <your product model>'
      print 'id mfg_serial <your product serial>'
      print 'id dev_id {}'.format (info.dsn)
      print 'file start 0'
      s = pubkey
      len = 80
      while s:
        print 'file add {}'.format (s[:len])
        s = s[len:]
      print 'conf save'
      print 'oem key <your oem key>'
      print 'client server region cn'
      print 'setup_mode disable'
    except:
      import traceback
      traceback.print_exc ()

#***************************************************************************************************
