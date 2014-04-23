import pickle

#pickle and load merkle trees

def pickle_data(mt, filename):
    handle = open(filename, 'wb')
    pickle.dump(a, handle)
    handle.close()
    return

def unpickle_data(filename):
    handle = open(filename, 'rb')
    return pickle.load(handle)
