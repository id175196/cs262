#!/usr/bin/env python

import os
import hashlib

class MarkleTree:
    def __init__(self, root, salt=''):
        self._linelength = 30
        self._root = root
        self._mt = {}
        self._hashlist = {}
        self._tophash = ''
        self.__MT__(salt)

    def Line(self):
        print self._linelength*'-'

    def PrintHashList(self):
        self.Line()
        for item, itemhash in self._hashlist.iteritems():
            print "%s %s" % (itemhash, item)
        self.Line()
        return

    def PrintMT(self, hash):
        value = self._mt[hash]
        item = value[0]
        child = value[1]
        print "%s %s" % (hash, item)
        if not child:
            return
        for itemhash, item in child.iteritems():  
            print "    -> %s %s" % (itemhash, item)
        for itemhash, item in child.iteritems():  
            self.PrintMT(itemhash)

    def MT(self):
        for node, hash in self._hashlist.iteritems():
            items = self.GetItems(node)
            value = []
            value.append(node)
            list = {}
            for item in items:
                if node == self._root:
                    list[self._hashlist[item]] = item
                else: 
                    list[self._hashlist[os.path.join(node, item)]] = os.path.join(node, item)
            value.append(list)
            self._mt[hash] = value
        self._tophash = self._hashlist[self._root]

    def __MT__(self, salt=''):
        self.HashList(self._root, salt)
        #self.PrintHashList()
        self.MT()
        print "Merkle Tree for %s: " % self._root
        self.PrintMT(self._tophash)
        self.Line()

    def md5sum(self, data, salt=''):
        m = hashlib.md5()
        fn = os.path.join(self._root, data)
        if os.path.isfile(fn):
            try:   
                f = file(fn, 'rb')
            except:
                return 'ERROR: unable to open %s' % fn
            while True:
                d = f.read(8096)
                if not d:
                    break
                m.update(d)
            m.update(salt)
            f.close()
        else:
            m.update(data)
        return m.hexdigest()

    def GetItems(self, directory):
        value = []
        if directory != self._root:
            directory = os.path.join(self._root, directory)
        if os.path.isdir(directory):
            items = os.listdir(directory)
            for item in items:
                value.append(item)
                #value.append(os.path.join(".", item))
            value.sort()
        return value
    
    def HashList(self, rootdir, salt=''):
        self.HashListChild(rootdir)
        items = self.GetItems(rootdir)
        if not items:
            self._hashlist[rootdir] = ''
            return
        s = ''
        for subitem in items:
            s = s + self._hashlist[subitem]
        self._hashlist[rootdir] = self.md5sum(s, salt)

    def HashListChild(self, rootdir):
        items = self.GetItems(rootdir)
        if not items:
            self._hashlist[rootdir] = ''
            return
        for item in items:
            itemname = os.path.join(rootdir, item)
            if os.path.isdir(itemname):
                self.HashListChild(item)
                subitems = self.GetItems(item)
                s = ''
                for subitem in subitems:
                    s = s + self._hashlist[os.path.join(item, subitem)]
                if rootdir == self._root:
                    self._hashlist[item] = self.md5sum(s)
                else:
                    self._hashlist[itemname] = self.md5sum(s)
            else:
                if rootdir == self._root:
                    self._hashlist[item] = self.md5sum(item)
                else:
                    self._hashlist[itemname] = self.md5sum(itemname)
 
def MTDiff(mt_a, a_tophash, mt_b, b_tophash):
    if a_tophash == b_tophash:
        print "Top hash is equal for %s and %s" % (mt_a._root, mt_b._root)
    else:
        a_value = mt_a._mt[a_tophash] 
        a_child = a_value[1]    # retrive the child list for merkle tree a
        b_value = mt_b._mt[b_tophash] 
        b_child = b_value[1]    # retrive the child list for merkle tree b

        for itemhash, item in a_child.iteritems():
            try:
                if b_child[itemhash] == item:
                    print "Info: SAME : %s" % item
            except:
                print "Info: DIFFERENT : %s" % item
                temp_value = mt_a._mt[itemhash]
                if len(temp_value[1]) > 0:      # check if this is a directory
                    diffhash = list(set(b_child.keys()) - set(a_child.keys()))
                    MTDiff(mt_a, itemhash, mt_b, diffhash[0])

    return

#function that returns list of files mt_a is missing
def mtMissLocs(mt_a, a_tophash, mt_b, b_tophash):
    deleted_files = list()
    if a_tophash != b_tophash:
        a_value = mt_a._mt[a_tophash] 
        a_child = a_value[1]    # retrive the child list for merkle tree a
        b_value = mt_b._mt[b_tophash] 
        b_child = b_value[1]    # retrive the child list for merkle tree b
        for itemhash, item in b_child.iteritems():
            if not (itemhash in a_child):
                print "Info: Missing : %s" % item
                deleted_files.append(item)
            try:
                if a_child[itemhash] == item:
                    skip = 1
            except:
                temp_value = mt_b._mt[itemhash]
                if len(temp_value[1]) > 0:      # check if this is a directory
                    diffhash = list(set(b_child.keys()) - set(a_child.keys()))
                    deleted_files += mtMissLocs(mt_a, itemhash, mt_b, diffhash[0])

    return deleted_files

#This is my slightly different version of MTDiff where it returns a list of
#file locations that are different
#assumes the first tree is the newer and the second tree is the older
def mtDiffLocs(mt_a, a_tophash, mt_b, b_tophash):
    diffs = list()
    if a_tophash != b_tophash:
        a_value = mt_a._mt[a_tophash] 
        a_child = a_value[1]    # retrive the child list for merkle tree a
        b_value = mt_b._mt[b_tophash] 
        b_child = b_value[1]    # retrive the child list for merkle tree b
        for itemhash, item in a_child.iteritems():
            if not (itemhash in b_child):
                diffs.append(item)
            try:
                if b_child[itemhash] == item:
                    print "Info: SAME : %s" % item
            except:
                print "Info: DIFFERENT : %s" % item
                temp_value = mt_a._mt[itemhash]
                if len(temp_value[1]) > 0:      # check if this is a directory
                    diffhash = list(set(b_child.keys()) - set(a_child.keys()))
                    diffs += mtDiffLocs(mt_a, itemhash, mt_b, diffhash[0])
                else:
                    diffs.append(item)
    return diffs

#function that takes two merkle trees and returns the updated files in the first
# (including added files) and a second list with files that the second tree
# has that the first does not.

def mtLocs(mt_a,mt_b):
    a_tophash = mt_a._tophash
    b_tophash = mt_b._tophash
    return(mtDiffLocs(mt_a, mt_a._tophash, mt_b, mt_b._tophash), mtMissLocs(mt_a, mt_a._tophash, mt_b, mt_b._tophash))


# Newly added function by Esmail Fadae.
# A modified copy of other functions elsewhere in this file that returns lists of updated files (without directories) and deleted files.
def mt_file_diffs(mt_new, mt_old):
  """
  Determine which files in a directory have been changed or deleted by comparing 
  a new Merkel tree of it to an older one.
  """
  updated_files = list()
  if a_tophash != b_tophash:
    a_value = mt_a._mt[a_tophash] 
    a_child = a_value[1]    # retrive the child list for merkle tree a
    b_value = mt_b._mt[b_tophash] 
    b_child = b_value[1]    # retrive the child list for merkle tree b
    for itemhash, item in a_child.iteritems():
      if (itemhash not in b_child) and \
        (os.path.isfile(os.path.join(mt_new._root, item))):
        updated_files.append(item)
      try:
        if b_child[itemhash] == item:
          None
      except:
        temp_value = mt_a._mt[itemhash]
        if len(temp_value[1]) > 0:      # check if this is a directory
          diffhash = list(set(b_child.keys()) - set(a_child.keys()))
          updated_files += mtDiffLocs(mt_a, itemhash, mt_b, diffhash[0])
        elif (os.path.isfile(os.path.join(mt_new._root, item))):
            updated_files.append(item)
  
  deleted_files = list()
  if a_tophash != b_tophash:
    a_value = mt_a._mt[a_tophash] 
    a_child = a_value[1]    # retrive the child list for merkle tree a
    b_value = mt_b._mt[b_tophash] 
    b_child = b_value[1]    # retrive the child list for merkle tree b
    for itemhash, item in b_child.iteritems():
      if not(item in a_child.values()):
        None
        deleted_files.append(item)
      try:
        if a_child[itemhash] == item:
          skip = 1
      except:
        temp_value = mt_b._mt[itemhash]
        if len(temp_value[1]) > 0:      # check if this is a directory
          diffhash = list(set(b_child.keys()) - set(a_child.keys()))
          deleted_files += mtMissLocs(mt_a, itemhash, mt_b, diffhash[0])
          
  return updated_files, deleted_files


#if __name__ == "__main__":
mt_a = MarkleTree('testA')
print mt_a._mt
mt_b = MarkleTree('testB')
#MTDiff(mt_a, mt_a._tophash, mt_b, mt_b._tophash)
vals = mtDiffLocs(mt_a, mt_a._tophash, mt_b, mt_b._tophash)
#mtMissLocs(mt_a, mt_a._tophash, mt_b, mt_b._tophash)


a_tophash = mt_a._tophash
b_tophash = mt_b._tophash
deleted_files = list()
if a_tophash != b_tophash:
    a_value = mt_a._mt[a_tophash] 
    a_child = a_value[1]    # retrive the child list for merkle tree a
    b_value = mt_b._mt[b_tophash] 
    b_child = b_value[1]    # retrive the child list for merkle tree b
    for itemhash, item in b_child.iteritems():
        if not(item in a_child.values()):
            print "Info: Missing : %s" % item
            deleted_files.append(item)
        try:
            if a_child[itemhash] == item:
                skip = 1
        except:
            temp_value = mt_b._mt[itemhash]
            if len(temp_value[1]) > 0:      # check if this is a directory
                diffhash = list(set(b_child.keys()) - set(a_child.keys()))
                deleted_files += mtMissLocs(mt_a, itemhash, mt_b, diffhash[0])



