import pickle, mt, os

#set the path
path = '.'

#pickle and load merkle trees

def pickle_mt(mt, filename):
    handle = open(filename, 'wb')
    pickle.dump(a, handle)
    return

def unpickle_mt(filename):
    handle = open('filename.pickle', 'rb')
    return pickle.load(handle)


#create merkle tree for a given uuid
def make_mt(uuid):
    mtree = mt.MarkleTree(path+ uuid + '/files')
    backup_files = path+ uuid + '/bookkeeping'
    if(backup_files) != True):
          os.makedirs(backup_files)
    mtree_filename = backup_files + '/mtree.mt'
    pickle_mt(mtree,mtree_filename)
    return

#get merkle tree for a given uuid
def get_mt(uuid):
    mtree_filename = path+ uuid + '/bookkeeping/mtree.mt'
    return unpickle_mt(mtree_filename)

#
